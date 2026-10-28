package drone

import "math"

// vec is a position in metres east (x) and north (y) of the projection's origin.
type vec struct{ x, y float64 }

// projection is an equirectangular projection about the dock: exact enough
// for a site within maxSpanM of it, and the same in the check as in the fence.
type projection struct {
	lat0, lon0, kx, ky float64
}

const earthRadiusM = 6371008.8

func newProjection(o Point) projection {
	ky := earthRadiusM * math.Pi / 180
	return projection{lat0: o.Lat, lon0: o.Lon, kx: ky * math.Cos(o.Lat*math.Pi/180), ky: ky}
}

func (pr projection) local(q Point) vec {
	return vec{(q.Lon - pr.lon0) * pr.kx, (q.Lat - pr.lat0) * pr.ky}
}

func sub(a, b vec) vec           { return vec{a.x - b.x, a.y - b.y} }
func cross(a, b vec) float64     { return a.x*b.y - a.y*b.x }
func dot(a, b vec) float64       { return a.x*b.x + a.y*b.y }
func orient(a, b, c vec) float64 { return cross(sub(b, a), sub(c, a)) }

// inside is the even-odd test; a point on an edge is never inside by the
// margin, which edgeDist enforces.
func inside(v vec, poly []vec) bool {
	in := false
	for i, j := 0, len(poly)-1; i < len(poly); j, i = i, i+1 {
		a, b := poly[i], poly[j]
		if (a.y > v.y) != (b.y > v.y) && v.x < (b.x-a.x)*(v.y-a.y)/(b.y-a.y)+a.x {
			in = !in
		}
	}
	return in
}

func pointSegDist(p, a, b vec) float64 {
	ab, ap := sub(b, a), sub(p, a)
	l := dot(ab, ab)
	t := 0.0
	if l > 0 {
		t = math.Max(0, math.Min(1, dot(ap, ab)/l))
	}
	d := sub(p, vec{a.x + t*ab.x, a.y + t*ab.y})
	return math.Hypot(d.x, d.y)
}

func segsIntersect(a, b, c, d vec) bool {
	d1, d2 := orient(c, d, a), orient(c, d, b)
	d3, d4 := orient(a, b, c), orient(a, b, d)
	if ((d1 > 0 && d2 < 0) || (d1 < 0 && d2 > 0)) && ((d3 > 0 && d4 < 0) || (d3 < 0 && d4 > 0)) {
		return true
	}
	return (d1 == 0 && pointSegDist(a, c, d) == 0) || (d2 == 0 && pointSegDist(b, c, d) == 0) ||
		(d3 == 0 && pointSegDist(c, a, b) == 0) || (d4 == 0 && pointSegDist(d, a, b) == 0)
}

func segSegDist(a, b, c, d vec) float64 {
	if segsIntersect(a, b, c, d) {
		return 0
	}
	return math.Min(math.Min(pointSegDist(a, c, d), pointSegDist(b, c, d)),
		math.Min(pointSegDist(c, a, b), pointSegDist(d, a, b)))
}

func edgeDist(v vec, poly []vec) float64 {
	m := math.Inf(1)
	for i := range poly {
		m = math.Min(m, pointSegDist(v, poly[i], poly[(i+1)%len(poly)]))
	}
	return m
}

func polySegDist(a, b vec, poly []vec) float64 {
	m := math.Inf(1)
	for i := range poly {
		m = math.Min(m, segSegDist(a, b, poly[i], poly[(i+1)%len(poly)]))
	}
	return m
}

// simple reports a polygon with distinct vertices, nonzero area and no two
// edges meeting except adjacent edges at their shared vertex.
func simple(poly []vec) bool {
	n := len(poly)
	area := 0.0
	for i := range poly {
		area += cross(poly[i], poly[(i+1)%n])
		for j := i + 1; j < n; j++ {
			if poly[i] == poly[j] {
				return false
			}
		}
	}
	if math.Abs(area) < 1e-6 {
		return false
	}
	for i := 0; i < n; i++ {
		a, b := poly[i], poly[(i+1)%n]
		for j := i + 1; j < n; j++ {
			c, d := poly[j], poly[(j+1)%n]
			adjacent := j == i+1 || (i == 0 && j == n-1)
			if adjacent {
				// Adjacent edges share one vertex; they may not fold back onto each other.
				var shared, p, q vec
				if j == i+1 {
					shared, p, q = b, a, d
				} else {
					shared, p, q = a, b, c
				}
				if orient(p, shared, q) == 0 && dot(sub(p, shared), sub(q, shared)) > 0 {
					return false
				}
				continue
			}
			if segsIntersect(a, b, c, d) {
				return false
			}
		}
	}
	return true
}
