package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"strconv"

	"github.com/ecadlabs/go-pkcs11/pkcs11"
)

var allAttrs = []pkcs11.AttributeType{
	pkcs11.AttributeClass,
	pkcs11.AttributeToken,
	pkcs11.AttributePrivate,
	pkcs11.AttributeLabel,
	pkcs11.AttributeUniqueID,
	pkcs11.AttributeApplication,
	pkcs11.AttributeValue,
	pkcs11.AttributeObjectID,
	pkcs11.AttributeCertificateType,
	pkcs11.AttributeIssuer,
	pkcs11.AttributeSerialNumber,
	pkcs11.AttributeACIssuer,
	pkcs11.AttributeOwner,
	pkcs11.AttributeAttrTypes,
	pkcs11.AttributeTrusted,
	pkcs11.AttributeCertificateCategory,
	pkcs11.AttributeJavaMIDPSecurityDomain,
	pkcs11.AttributeURL,
	pkcs11.AttributeHashOfSubjectPublicKey,
	pkcs11.AttributeHashOfIssuerPublicKey,
	pkcs11.AttributeNameHashAlgorithm,
	pkcs11.AttributeCheckValue,
	pkcs11.AttributeKeyType,
	pkcs11.AttributeSubject,
	pkcs11.AttributeID,
	pkcs11.AttributeSensitive,
	pkcs11.AttributeEncrypt,
	pkcs11.AttributeDecrypt,
	pkcs11.AttributeWrap,
	pkcs11.AttributeUnwrap,
	pkcs11.AttributeSign,
	pkcs11.AttributeSignRecover,
	pkcs11.AttributeVerify,
	pkcs11.AttributeVerifyRecover,
	pkcs11.AttributeDerive,
	pkcs11.AttributeStartDate,
	pkcs11.AttributeEndDate,
	pkcs11.AttributeModulus,
	pkcs11.AttributeModulusBits,
	pkcs11.AttributePublicExponent,
	pkcs11.AttributePrivateExponent,
	pkcs11.AttributePrime_1,
	pkcs11.AttributePrime_2,
	pkcs11.AttributeExponent_1,
	pkcs11.AttributeExponent_2,
	pkcs11.AttributeCoefficient,
	pkcs11.AttributePublicKeyInfo,
	pkcs11.AttributePrime,
	pkcs11.AttributeSubprime,
	pkcs11.AttributeBase,
	pkcs11.AttributePrimeBits,
	pkcs11.AttributeSubPrimeBits,
	pkcs11.AttributeValueBits,
	pkcs11.AttributeValueLen,
	pkcs11.AttributeExtractable,
	pkcs11.AttributeLocal,
	pkcs11.AttributeNeverExtractable,
	pkcs11.AttributeAlwaysSensitive,
	pkcs11.AttributeKeyGenMechanism,
	pkcs11.AttributeModifiable,
	pkcs11.AttributeCopyable,
	pkcs11.AttributeDestroyable,
	pkcs11.AttributeECParams,
	pkcs11.AttributeECPoint,
	pkcs11.AttributeAlwaysAuthenticate,
	pkcs11.AttributeWrapWithTrusted,
	pkcs11.AttributeWrapTemplate,
	pkcs11.AttributeUnwrapTemplate,
	pkcs11.AttributeDeriveTemplate,
	pkcs11.AttributeOTPFormat,
	pkcs11.AttributeOTPLength,
	pkcs11.AttributeOTPTimeInterval,
	pkcs11.AttributeOTPUserFriendlyMode,
	pkcs11.AttributeOTPChallengeRequirement,
	pkcs11.AttributeOTPTimeRequirement,
	pkcs11.AttributeOTPCounterRequirement,
	pkcs11.AttributeOTPPinRequirement,
	pkcs11.AttributeOTPCounter,
	pkcs11.AttributeOTPTime,
	pkcs11.AttributeOTPUserIdentifier,
	pkcs11.AttributeOTPServiceIdentifier,
	pkcs11.AttributeOTPServiceLogo,
	pkcs11.AttributeOTPServiceLogoType,
	pkcs11.AttributeGOSTR3410Params,
	pkcs11.AttributeGOSTR3411Params,
	pkcs11.AttributeGOST28147Params,
	pkcs11.AttributeHWFeatureType,
	pkcs11.AttributeResetOnInit,
	pkcs11.AttributeHasReset,
	pkcs11.AttributePixelX,
	pkcs11.AttributePixelY,
	pkcs11.AttributeResolution,
	pkcs11.AttributeCharRows,
	pkcs11.AttributeCharColumns,
	pkcs11.AttributeColor,
	pkcs11.AttributeBitsPerPixel,
	pkcs11.AttributeCharSets,
	pkcs11.AttributeEncodingMethods,
	pkcs11.AttributeMimeTypes,
	pkcs11.AttributeMechanismType,
	pkcs11.AttributeRequiredCMSAttributes,
	pkcs11.AttributeDefaultCMSAttributes,
	pkcs11.AttributeSupportedCMSAttributes,
	pkcs11.AttributeAllowedMechanisms,
	pkcs11.AttributeProfileID,
	pkcs11.AttributeX2RatchetBag,
	pkcs11.AttributeX2RatchetBagSize,
	pkcs11.AttributeX2RatchetBobs1stMsg,
	pkcs11.AttributeX2RatchetCKR,
	pkcs11.AttributeX2RatchetCKS,
	pkcs11.AttributeX2RatchetDHP,
	pkcs11.AttributeX2RatchetDHR,
	pkcs11.AttributeX2RatchetDHS,
	pkcs11.AttributeX2RatchetHKR,
	pkcs11.AttributeX2RatchetHKS,
	pkcs11.AttributeX2RatchetIsAlice,
	pkcs11.AttributeX2RatchetNHKR,
	pkcs11.AttributeX2RatchetNHKS,
	pkcs11.AttributeX2RatchetNR,
	pkcs11.AttributeX2RatchetNS,
	pkcs11.AttributeX2RatchetPNS,
	pkcs11.AttributeX2RatchetRK,
	pkcs11.AttributeHSSLevels,
	pkcs11.AttributeHSSLMSType,
	pkcs11.AttributeHSSLMOTSType,
	pkcs11.AttributeHSSLMSTypes,
	pkcs11.AttributeHSSLMOTSTypes,
	pkcs11.AttributeHSSKeysRemaining,
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

		values := make([]pkcs11.TypeValue, len(allAttrs))
		for i, a := range allAttrs {
			values[i] = pkcs11.NewTypeValue(a)
		}
		if err := obj.GetAttributes(values...); err != nil && !errors.Is(err, pkcs11.ErrAttributeTypeInvalid) && !errors.Is(err, pkcs11.ErrAttributeSensitive) {
			log.Fatal(err)
		}
		for _, v := range values {
			if v.Value.IsNil() {
				continue
			}
			fmt.Printf("\t%v: %v\n", v.Type, v)
		}
		fmt.Printf("\n")
	}
}
