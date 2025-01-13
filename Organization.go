package model

import (
	"crypto/sha256"
	"fmt"

	"github.com/Nik-U/pbc"
)

type Org struct {
	APKMap   map[string]*APK
	ASKMap   map[string]*ASK
	Name     string
	EGGAlpha *pbc.Element `field:"2"`
	Alpha    *pbc.Element `field:"3"`
	GAlpha   *pbc.Element `field:"0"`
}

func (o *Org) GetPK() *pbc.Element {
	return o.EGGAlpha
}

func (o *Org) GetAPKMap() map[string]*APK {
	return o.APKMap
}

func (o *Org) GenerateNewAttr(attr string, d *DABE) (*APK, error) {
	if o.APKMap[attr] != nil || o.ASKMap[attr] != nil {
		return nil, fmt.Errorf("already has this attr:%s", attr)
	}
	y := d.CurveParam.GetNewZn()
	sk := ASK{y}
	gy := d.G.NewFieldElement().PowZn(d.G, y)
	pk := APK{gy}
	o.APKMap[attr] = &pk
	o.ASKMap[attr] = &sk
	// o.AttrMap[attr] = &AttrUser{0, make(map[string]*pbc.Element)}
	return &pk, nil
}

func (o *Org) KeyGenByUser(gid string, attr string, d *DABE) (*pbc.Element, error) {
	if o.ASKMap[attr] == nil {
		return nil, fmt.Errorf("don't have this attr, error when %s", attr)
	}
	hashGid := d.CurveParam.GetG1FromStringHash(gid, sha256.New())
	key := hashGid.
		ThenPowZn(o.ASKMap[attr].Y).
		ThenMul(o.GAlpha)
	return key, nil
}
