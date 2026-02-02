package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"strconv"

	"github.com/ecadlabs/go-pkcs11/pkcs11"
	"github.com/ecadlabs/go-pkcs11/pkcs11/attr"
)

func newAttributeTable() []attr.Attribute {
	return []attr.Attribute{
		new(attr.AttrClass),
		new(attr.AttrToken),
		new(attr.AttrPrivate),
		new(attr.AttrLabel),
		new(attr.AttrUniqueID),
		new(attr.AttrApplication),
		new(attr.AttrValue),
		new(attr.AttrObjectID),
		new(attr.AttrCertificateType),
		new(attr.AttrIssuer),
		new(attr.AttrSerialNumber),
		new(attr.AttrACIssuer),
		new(attr.AttrOwner),
		new(attr.AttrAttrTypes),
		new(attr.AttrTrusted),
		new(attr.AttrCertificateCategory),
		new(attr.AttrJavaMIDPSecurityDomain),
		new(attr.AttrURL),
		new(attr.AttrHashOfSubjectPublicKey),
		new(attr.AttrHashOfIssuerPublicKey),
		new(attr.AttrNameHashAlgorithm),
		new(attr.AttrCheckValue),
		new(attr.AttrKeyType),
		new(attr.AttrSubject),
		new(attr.AttrID),
		new(attr.AttrSensitive),
		new(attr.AttrEncrypt),
		new(attr.AttrDecrypt),
		new(attr.AttrWrap),
		new(attr.AttrUnwrap),
		new(attr.AttrSign),
		new(attr.AttrSignRecover),
		new(attr.AttrVerify),
		new(attr.AttrVerifyRecover),
		new(attr.AttrDerive),
		new(attr.AttrStartDate),
		new(attr.AttrEndDate),
		new(attr.AttrModulus),
		new(attr.AttrModulusBits),
		new(attr.AttrPublicExponent),
		new(attr.AttrPrivateExponent),
		new(attr.AttrPrime_1),
		new(attr.AttrPrime_2),
		new(attr.AttrExponent_1),
		new(attr.AttrExponent_2),
		new(attr.AttrCoefficient),
		new(attr.AttrPublicKeyInfo),
		new(attr.AttrPrime),
		new(attr.AttrSubprime),
		new(attr.AttrBase),
		new(attr.AttrPrimeBits),
		new(attr.AttrSubPrimeBits),
		new(attr.AttrValueBits),
		new(attr.AttrValueLen),
		new(attr.AttrExtractable),
		new(attr.AttrLocal),
		new(attr.AttrNeverExtractable),
		new(attr.AttrAlwaysSensitive),
		new(attr.AttrKeyGenMechanism),
		new(attr.AttrModifiable),
		new(attr.AttrCopyable),
		new(attr.AttrDestroyable),
		new(attr.AttrECParams),
		new(attr.AttrECPoint),
		new(attr.AttrAlwaysAuthenticate),
		new(attr.AttrWrapWithTrusted),
		new(attr.AttrWrapTemplate),
		new(attr.AttrUnwrapTemplate),
		new(attr.AttrDeriveTemplate),
		new(attr.AttrOTPFormat),
		new(attr.AttrOTPLength),
		new(attr.AttrOTPTimeInterval),
		new(attr.AttrOTPUserFriendlyMode),
		new(attr.AttrOTPChallengeRequirement),
		new(attr.AttrOTPTimeRequirement),
		new(attr.AttrOTPCounterRequirement),
		new(attr.AttrOTPPinRequirement),
		new(attr.AttrOTPCounter),
		new(attr.AttrOTPTime),
		new(attr.AttrOTPUserIdentifier),
		new(attr.AttrOTPServiceIdentifier),
		new(attr.AttrOTPServiceLogo),
		new(attr.AttrOTPServiceLogoType),
		new(attr.AttrGOSTR3410Params),
		new(attr.AttrGOSTR3411Params),
		new(attr.AttrGOST28147Params),
		new(attr.AttrHWFeatureType),
		new(attr.AttrResetOnInit),
		new(attr.AttrHasReset),
		new(attr.AttrPixelX),
		new(attr.AttrPixelY),
		new(attr.AttrResolution),
		new(attr.AttrCharRows),
		new(attr.AttrCharColumns),
		new(attr.AttrColor),
		new(attr.AttrBitsPerPixel),
		new(attr.AttrCharSets),
		new(attr.AttrEncodingMethods),
		new(attr.AttrMimeTypes),
		new(attr.AttrMechanismType),
		new(attr.AttrRequiredCMSAttributes),
		new(attr.AttrDefaultCMSAttributes),
		new(attr.AttrSupportedCMSAttributes),
		new(attr.AttrAllowedMechanisms),
		new(attr.AttrProfileID),
		new(attr.AttrX2RatchetBag),
		new(attr.AttrX2RatchetBagSize),
		new(attr.AttrX2RatchetBobs1stMsg),
		new(attr.AttrX2RatchetCKR),
		new(attr.AttrX2RatchetCKS),
		new(attr.AttrX2RatchetDHP),
		new(attr.AttrX2RatchetDHR),
		new(attr.AttrX2RatchetDHS),
		new(attr.AttrX2RatchetHKR),
		new(attr.AttrX2RatchetHKS),
		new(attr.AttrX2RatchetIsAlice),
		new(attr.AttrX2RatchetNHKR),
		new(attr.AttrX2RatchetNHKS),
		new(attr.AttrX2RatchetNR),
		new(attr.AttrX2RatchetNS),
		new(attr.AttrX2RatchetPNS),
		new(attr.AttrX2RatchetRK),
		new(attr.AttrHSSLevels),
		new(attr.AttrHSSLMSType),
		new(attr.AttrHSSLMOTSType),
		new(attr.AttrHSSLMSTypes),
		new(attr.AttrHSSLMOTSTypes),
		new(attr.AttrHSSKeysRemaining),
	}
}

func main() {
	var (
		modPath string
		slot    string
		pin     string
	)

	flag.StringVar(&modPath, "mod", "", "Module path")
	flag.StringVar(&slot, "slot", "", "Slot ID")
	flag.StringVar(&pin, "pin", "", "User PIN")
	flag.Parse()

	mod, err := pkcs11.Open(modPath, pkcs11.OptOsLockingOk)
	if err != nil {
		log.Fatal(err)
	}

	var (
		slotID   uint
		slotInfo *pkcs11.SlotInfo
	)

	if slot != "" {
		v, err := strconv.ParseUint(slot, 0, 64)
		if err != nil {
			log.Fatal(err)
		}
		slotID = uint(v)
		if slotInfo, err = mod.SlotInfo(slotID); err != nil {
			log.Fatal(err)
		}
	} else {
		slots, err := mod.SlotIDs()
		if err != nil {
			log.Fatal(err)
		}
		for _, s := range slots {
			si, err := mod.SlotInfo(s)
			if err != nil {
				log.Fatal(err)
			}
			if si.Token != nil {
				slotInfo = si
				slotID = s
				break
			}
		}
		if slotInfo == nil {
			log.Fatal("token not found")
		}
	}

	fmt.Printf(
		"Slot ID: %#016x\nDescription: %v\nManufacturer: %v\nFlags: %v\nHardwareVersion: %v\nFirmwareVersion: %v\n\n",
		slotID,
		slotInfo.Description,
		slotInfo.Manufacturer,
		slotInfo.Flags,
		slotInfo.HardwareVersion,
		slotInfo.FirmwareVersion,
	)

	if slotInfo.Token == nil {
		return
	}

	fmt.Printf("Token:\n")
	fmt.Printf(
		"\tLabel: %v\n\tManufacturer: %v\n\tModel: %v\n\tSerialNumber: %v\n\tFlags: %v\n\tMaxSessionCount: %v\n\tSessionCount: %v\n\tMaxRwSessionCount: %v\n\tRwSessionCount: %v\n\tMaxPinLen: %v\n\tMinPinLen: %v\n\tTotalPublicMemory: %v\n\tFreePublicMemory: %v\n\tTotalPrivateMemory: %v\n\tFreePrivateMemory: %v\n\tHardwareVersion: %v\n\tFirmwareVersion: %v\n\tUTCTime: %v\n\n",
		slotInfo.Token.Label,
		slotInfo.Token.Manufacturer,
		slotInfo.Token.Model,
		slotInfo.Token.SerialNumber,
		slotInfo.Token.Flags,
		slotInfo.Token.MaxSessionCount,
		slotInfo.Token.SessionCount,
		slotInfo.Token.MaxRwSessionCount,
		slotInfo.Token.RwSessionCount,
		slotInfo.Token.MaxPinLen,
		slotInfo.Token.MinPinLen,
		slotInfo.Token.TotalPublicMemory,
		slotInfo.Token.FreePublicMemory,
		slotInfo.Token.TotalPrivateMemory,
		slotInfo.Token.FreePrivateMemory,
		slotInfo.Token.HardwareVersion,
		slotInfo.Token.FirmwareVersion,
		slotInfo.Token.UTCTime,
	)

	if slotInfo.Token.Flags&pkcs11.TokenTokenInitialized == 0 {
		return
	}

	session, err := mod.NewSession(slotID, pkcs11.OptUserPIN(pin))
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	objects, err := session.Objects()
	if err != nil {
		log.Fatal(err)
	}
	for _, obj := range objects {
		fmt.Printf("Object(%#016x):\n", obj.Handle())

		values := newAttributeTable()
		if err := obj.GetAttributes(values...); err != nil && !errors.Is(err, pkcs11.ErrAttributeTypeInvalid) && !errors.Is(err, pkcs11.ErrAttributeSensitive) {
			log.Fatal(err)
		}
		for _, v := range values {
			if v.IsNil() {
				continue
			}
			fmt.Printf("\t%v: %v\n", v.Type(), v)
		}
		fmt.Printf("\n")
	}
}
