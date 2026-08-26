#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <ntimage.h>
#include "stdlib.h"
#include "stdio.h"


namespace Random {
    const char* ssdM2ModelNames[] = {
        oxorany("Samsung QuantumDrive 2000 HDD"),
        oxorany("Samsung EvoBoost SSD 2800"),
        oxorany("Samsung TitanFlash M.2 3600"),
        oxorany("Samsung VelocityDrive 2200 HDD"),
        oxorany("Samsung UltraBeam SSD 3200"),
        oxorany("Samsung FlashCore M.2 3800"),
        oxorany("Samsung PowerSpin 2400 HDD"),
        oxorany("Samsung TurboShift SSD 3000"),
        oxorany("Samsung ThunderCore M.2 4000"),
        oxorany("Samsung ProSpeed 2600 HDD"),
        oxorany("Samsung UltraSonic SSD 3400"),
        oxorany("Samsung HyperCore M.2 4200"),
        oxorany("Samsung UltraMax 2800 HDD"),
        oxorany("Samsung MegaFlash SSD 3600"),
        oxorany("Samsung QuantumCore M.2 4400"),
        oxorany("Samsung TurboFire 3000 HDD"),
        oxorany("Samsung EvoDrive SSD 3800"),
        oxorany("Samsung TurboFusion M.2 4600"),
        oxorany("Samsung UltraSpeed 3200 HDD"),
        oxorany("Samsung PowerFlash SSD 4000"),
        oxorany("Samsung HyperDrive M.2 4800"),
        oxorany("Samsung MegaSpin 3400 HDD"),
        oxorany("Samsung QuantumBoost SSD 4200"),
        oxorany("Samsung UltraBoost M.2 5000"),
        oxorany("Samsung PowerCore 3600 HDD"),
        oxorany("Samsung VelocityBoost SSD 4400"),
        oxorany("Samsung FlashBoost M.2 5200"),
        oxorany("Samsung EvoSpin 3800 HDD"),
        oxorany("Samsung TurboDrive SSD 4600"),
        oxorany("Samsung QuantumFlash M.2 5400"),
        oxorany("Samsung TitanSpeed 4000 HDD"),
        oxorany("Samsung UltraShift SSD 4800"),
        oxorany("Samsung ThunderFlash M.2 5600"),
        oxorany("Samsung ProSpin 4200 HDD"),
        oxorany("Samsung PowerBoost SSD 5000"),
        oxorany("Samsung HyperFlash M.2 5800"),
        oxorany("Samsung UltraFire 4400 HDD"),
        oxorany("Samsung EvoBeam SSD 5200"),
        oxorany("Samsung TurboMax M.2 6000"),
        oxorany("Samsung QuantumSpeed 4600 HDD"),
        oxorany("Samsung MegaDrive SSD 5400"),
        oxorany("Samsung UltraVault M.2 6200"),
        oxorany("Samsung PowerSpeed 4800 HDD"),
        oxorany("Samsung VelocityCore SSD 5600"),
        oxorany("Samsung FlashShift M.2 6400"),
        oxorany("Samsung HyperSpin 5000 HDD"),
        oxorany("Samsung QuantumDrive SSD 5800"),
        oxorany("Samsung TurboBoost M.2 6600"),
        oxorany("Samsung UltraShift 5200 HDD"),
        oxorany("Samsung PowerDrive SSD 6000"),
        oxorany("Samsung EvoCore M.2 6800"),
        oxorany("Samsung MegaSpeed 5400 HDD"),
        oxorany("Samsung TurboFlash SSD 6200"),
        oxorany("Samsung QuantumBoost M.2 7000"),
        oxorany("Samsung UltraFlash 5600 HDD"),
        oxorany("Samsung VelocityBoost SSD 6400"),
        oxorany("Samsung FlashCore M.2 7200"),
        oxorany("Samsung EvoFire 5800 HDD"),
        oxorany("Samsung PowerBeam SSD 6600"),
        oxorany("Samsung HyperDrive M.2 7400"),
        oxorany("Samsung UltraSpin 6000 HDD"),
        oxorany("Samsung QuantumBoost SSD 6800"),
        oxorany("Samsung TitanCore M.2 7600"),
        oxorany("Samsung TurboSpeed 6200 HDD"),
        oxorany("Samsung UltraDrive SSD 7000"),
        oxorany("Samsung ThunderFlash M.2 7800"),
        oxorany("Samsung ProSpeed 6400 HDD"),
        oxorany("Samsung PowerBoost SSD 7200"),
        oxorany("Samsung HyperFlash M.2 8000"),
        oxorany("Samsung UltraFire 6600 HDD"),
        oxorany("Samsung EvoBeam SSD 7400"),
        oxorany("Samsung TurboVault M.2 8200"),
        oxorany("Samsung QuantumSpeed 6800 HDD"),
        oxorany("Samsung MegaDrive SSD 7600"),
        oxorany("Samsung UltraCore M.2 8400"),
        oxorany("Samsung PowerSpeed 7000 HDD"),
        oxorany("Samsung VelocityCore SSD 7800"),
        oxorany("Samsung FlashShift M.2 8600"),
        oxorany("Samsung HyperSpin 7200 HDD"),
        oxorany("Samsung QuantumDrive SSD 8000"),
        oxorany("Samsung TurboBoost M.2 8800"),
        oxorany("Samsung UltraShift 7400 HDD"),
        oxorany("Samsung PowerDrive SSD 8200"),
        oxorany("Samsung EvoCore M.2 9000"),
        oxorany("Samsung MegaSpeed 7600 HDD"),
        oxorany("Samsung TurboFlash SSD 8400"),
        oxorany("Samsung QuantumBoost M.2 9200"),
        oxorany("Samsung UltraFlash 7800 HDD"),
        oxorany("Samsung VelocityBoost SSD 8600"),
        oxorany("Samsung FlashCore M.2 9400"),
        oxorany("Samsung EvoFire 8000 HDD"),
        oxorany("Samsung PowerBeam SSD 8800"),
        oxorany("Samsung HyperDrive M.2 9600"),
        oxorany("Samsung UltraSpin 8200 HDD"),
        oxorany("Samsung QuantumBoost SSD 9000"),
        oxorany("Samsung TitanCore M.2 9800"),
        oxorany("Samsung TurboSpeed 8400 HDD"),
        oxorany("Samsung UltraDrive SSD 9200"),
        oxorany("Samsung ThunderFlash M.2 10000"),

        oxorany("Kingston QuantumDrive 2000 HDD"),
        oxorany("Kingston EvoBoost SSD 2800"),
        oxorany("Kingston TitanFlash M.2 3600"),
        oxorany("Kingston VelocityDrive 2200 HDD"),
        oxorany("Kingston UltraBeam SSD 3200"),
        oxorany("Kingston FlashCore M.2 3800"),
        oxorany("Kingston PowerSpin 2400 HDD"),
        oxorany("Kingston TurboShift SSD 3000"),
        oxorany("Kingston ThunderCore M.2 4000"),
        oxorany("Kingston ProSpeed 2600 HDD"),
        oxorany("Kingston UltraSonic SSD 3400"),
        oxorany("Kingston HyperCore M.2 4200"),
        oxorany("Kingston UltraMax 2800 HDD"),
        oxorany("Kingston MegaFlash SSD 3600"),
        oxorany("Kingston QuantumCore M.2 4400"),
        oxorany("Kingston TurboFire 3000 HDD"),
        oxorany("Kingston EvoDrive SSD 3800"),
        oxorany("Kingston TurboFusion M.2 4600"),
        oxorany("Kingston UltraSpeed 3200 HDD"),
        oxorany("Kingston PowerFlash SSD 4000"),
        oxorany("Kingston HyperDrive M.2 4800"),
        oxorany("Kingston MegaSpin 3400 HDD"),
        oxorany("Kingston QuantumBoost SSD 4200"),
        oxorany("Kingston UltraBoost M.2 5000"),
        oxorany("Kingston PowerCore 3600 HDD"),
        oxorany("Kingston VelocityBoost SSD 4400"),
        oxorany("Kingston FlashBoost M.2 5200"),
        oxorany("Kingston EvoSpin 3800 HDD"),
        oxorany("Kingston TurboDrive SSD 4600"),
        oxorany("Kingston QuantumFlash M.2 5400"),
        oxorany("Kingston TitanSpeed 4000 HDD"),
        oxorany("Kingston UltraShift SSD 4800"),
        oxorany("Kingston ThunderFlash M.2 5600"),
        oxorany("Kingston ProSpin 4200 HDD"),
        oxorany("Kingston PowerBoost SSD 5000"),
        oxorany("Kingston HyperFlash M.2 5800"),
        oxorany("Kingston UltraFire 4400 HDD"),
        oxorany("Kingston EvoBeam SSD 5200"),
        oxorany("Kingston TurboMax M.2 6000"),
        oxorany("Kingston QuantumSpeed 4600 HDD"),
        oxorany("Kingston MegaDrive SSD 5400"),
        oxorany("Kingston UltraVault M.2 6200"),
        oxorany("Kingston PowerSpeed 4800 HDD"),
        oxorany("Kingston VelocityCore SSD 5600"),
        oxorany("Kingston FlashShift M.2 6400"),
        oxorany("Kingston HyperSpin 5000 HDD"),
        oxorany("Kingston QuantumDrive SSD 5800"),
        oxorany("Kingston TurboBoost M.2 6600"),
        oxorany("Kingston UltraShift 5200 HDD"),
        oxorany("Kingston PowerDrive SSD 6000"),
        oxorany("Kingston EvoCore M.2 6800"),
        oxorany("Kingston MegaSpeed 5400 HDD"),
        oxorany("Kingston TurboFlash SSD 6200"),
        oxorany("Kingston QuantumBoost M.2 7000"),
        oxorany("Kingston UltraFlash 5600 HDD"),
        oxorany("Kingston VelocityBoost SSD 6400"),
        oxorany("Kingston FlashCore M.2 7200"),
        oxorany("Kingston EvoFire 5800 HDD"),
        oxorany("Kingston PowerBeam SSD 6600"),
        oxorany("Kingston HyperDrive M.2 7400"),
        oxorany("Kingston UltraSpin 6000 HDD"),
        oxorany("Kingston QuantumBoost SSD 6800"),
        oxorany("Kingston TitanCore M.2 7600"),
        oxorany("Kingston TurboSpeed 6200 HDD"),
        oxorany("Kingston UltraDrive SSD 7000"),
        oxorany("Kingston ThunderFlash M.2 7800"),
        oxorany("Kingston ProSpeed 6400 HDD"),
        oxorany("Kingston PowerBoost SSD 7200"),
        oxorany("Kingston HyperFlash M.2 8000"),
        oxorany("Kingston UltraFire 6600 HDD"),
        oxorany("Kingston EvoBeam SSD 7400"),
        oxorany("Kingston TurboVault M.2 8200"),
        oxorany("Kingston QuantumSpeed 6800 HDD"),
        oxorany("Kingston MegaDrive SSD 7600"),
        oxorany("Kingston UltraCore M.2 8400"),
        oxorany("Kingston PowerSpeed 7000 HDD"),
        oxorany("Kingston VelocityCore SSD 7800"),
        oxorany("Kingston FlashShift M.2 8600"),
        oxorany("Kingston HyperSpin 7200 HDD"),
        oxorany("Kingston QuantumDrive SSD 8000"),
        oxorany("Kingston TurboBoost M.2 8800"),
        oxorany("Kingston UltraShift 7400 HDD"),
        oxorany("Kingston PowerDrive SSD 8200"),
        oxorany("Kingston EvoCore M.2 9000"),
        oxorany("Kingston MegaSpeed 7600 HDD"),
        oxorany("Kingston TurboFlash SSD 8400"),
        oxorany("Kingston QuantumBoost M.2 9200"),
        oxorany("Kingston UltraFlash 7800 HDD"),
        oxorany("Kingston VelocityBoost SSD 8600"),
        oxorany("Kingston FlashCore M.2 9400"),
        oxorany("Kingston EvoFire 8000 HDD"),
        oxorany("Kingston PowerBeam SSD 8800"),
        oxorany("Kingston HyperDrive M.2 9600"),
        oxorany("Kingston UltraSpin 8200 HDD"),
        oxorany("Kingston QuantumBoost SSD 9000"),
        oxorany("Kingston TitanCore M.2 9800"),
        oxorany("Kingston TurboSpeed 8400 HDD"),
        oxorany("Kingston UltraDrive SSD 9200"),
        oxorany("Kingston ThunderFlash M.2 10000"),

        oxorany("HyperX QuantumDrive 2000 HDD"),
        oxorany("HyperX EvoBoost SSD 2800"),
        oxorany("HyperX TitanFlash M.2 3600"),
        oxorany("HyperX VelocityDrive 2200 HDD"),
        oxorany("HyperX UltraBeam SSD 3200"),
        oxorany("HyperX FlashCore M.2 3800"),
        oxorany("HyperX PowerSpin 2400 HDD"),
        oxorany("HyperX TurboShift SSD 3000"),
        oxorany("HyperX ThunderCore M.2 4000"),
        oxorany("HyperX ProSpeed 2600 HDD"),
        oxorany("HyperX UltraSonic SSD 3400"),
        oxorany("HyperX HyperCore M.2 4200"),
        oxorany("HyperX UltraMax 2800 HDD"),
        oxorany("HyperX MegaFlash SSD 3600"),
        oxorany("HyperX QuantumCore M.2 4400"),
        oxorany("HyperX TurboFire 3000 HDD"),
        oxorany("HyperX EvoDrive SSD 3800"),
        oxorany("HyperX TurboFusion M.2 4600"),
        oxorany("HyperX UltraSpeed 3200 HDD"),
        oxorany("HyperX PowerFlash SSD 4000"),
        oxorany("HyperX HyperDrive M.2 4800"),
        oxorany("HyperX MegaSpin 3400 HDD"),
        oxorany("HyperX QuantumBoost SSD 4200"),
        oxorany("HyperX UltraBoost M.2 5000"),
        oxorany("HyperX PowerCore 3600 HDD"),
        oxorany("HyperX VelocityBoost SSD 4400"),
        oxorany("HyperX FlashBoost M.2 5200"),
        oxorany("HyperX EvoSpin 3800 HDD"),
        oxorany("HyperX TurboDrive SSD 4600"),
        oxorany("HyperX QuantumFlash M.2 5400"),
        oxorany("HyperX TitanSpeed 4000 HDD"),
        oxorany("HyperX UltraShift SSD 4800"),
        oxorany("HyperX ThunderFlash M.2 5600"),
        oxorany("HyperX ProSpin 4200 HDD"),
        oxorany("HyperX PowerBoost SSD 5000"),
        oxorany("HyperX HyperFlash M.2 5800"),
        oxorany("HyperX UltraFire 4400 HDD"),
        oxorany("HyperX EvoBeam SSD 5200"),
        oxorany("HyperX TurboMax M.2 6000"),
        oxorany("HyperX QuantumSpeed 4600 HDD"),
        oxorany("HyperX MegaDrive SSD 5400"),
        oxorany("HyperX UltraVault M.2 6200"),
        oxorany("HyperX PowerSpeed 4800 HDD"),
        oxorany("HyperX VelocityCore SSD 5600"),
        oxorany("HyperX FlashShift M.2 6400"),
        oxorany("HyperX HyperSpin 5000 HDD"),
        oxorany("HyperX QuantumDrive SSD 5800"),
        oxorany("HyperX TurboBoost M.2 6600"),
        oxorany("HyperX UltraShift 5200 HDD"),
        oxorany("HyperX PowerDrive SSD 6000"),
        oxorany("HyperX EvoCore M.2 6800"),
        oxorany("HyperX MegaSpeed 5400 HDD"),
        oxorany("HyperX TurboFlash SSD 6200"),
        oxorany("HyperX QuantumBoost M.2 7000"),
        oxorany("HyperX UltraFlash 5600 HDD"),
        oxorany("HyperX VelocityBoost SSD 6400"),
        oxorany("HyperX FlashCore M.2 7200"),
        oxorany("HyperX EvoFire 5800 HDD"),
        oxorany("HyperX PowerBeam SSD 6600"),
        oxorany("HyperX HyperDrive M.2 7400"),
        oxorany("HyperX UltraSpin 6000 HDD"),
        oxorany("HyperX QuantumBoost SSD 6800"),
        oxorany("HyperX TitanCore M.2 7600"),
        oxorany("HyperX TurboSpeed 6200 HDD"),
        oxorany("HyperX UltraDrive SSD 7000"),
        oxorany("HyperX ThunderFlash M.2 7800"),
        oxorany("HyperX ProSpeed 6400 HDD"),
        oxorany("HyperX PowerBoost SSD 7200"),
        oxorany("HyperX HyperFlash M.2 8000"),
        oxorany("HyperX UltraFire 6600 HDD"),
        oxorany("HyperX EvoBeam SSD 7400"),
        oxorany("HyperX TurboVault M.2 8200"),
        oxorany("HyperX QuantumSpeed 6800 HDD"),
        oxorany("HyperX MegaDrive SSD 7600"),
        oxorany("HyperX UltraCore M.2 8400"),
        oxorany("HyperX PowerSpeed 7000 HDD"),
        oxorany("HyperX VelocityCore SSD 7800"),
        oxorany("HyperX FlashShift M.2 8600"),
        oxorany("HyperX HyperSpin 7200 HDD"),
        oxorany("HyperX QuantumDrive SSD 8000"),
        oxorany("HyperX TurboBoost M.2 8800"),
        oxorany("HyperX UltraShift 7400 HDD"),
        oxorany("HyperX PowerDrive SSD 8200"),
        oxorany("HyperX EvoCore M.2 9000"),
        oxorany("HyperX MegaSpeed 7600 HDD"),
        oxorany("HyperX TurboFlash SSD 8400"),
        oxorany("HyperX QuantumBoost M.2 9200"),
        oxorany("HyperX UltraFlash 7800 HDD"),
        oxorany("HyperX VelocityBoost SSD 8600"),
        oxorany("HyperX FlashCore M.2 9400"),
        oxorany("HyperX EvoFire 8000 HDD"),
        oxorany("HyperX PowerBeam SSD 8800"),
        oxorany("HyperX HyperDrive M.2 9600"),
        oxorany("HyperX UltraSpin 8200 HDD"),
        oxorany("HyperX QuantumBoost SSD 9000"),
        oxorany("HyperX TitanCore M.2 9800"),
        oxorany("HyperX TurboSpeed 8400 HDD"),
        oxorany("HyperX UltraDrive SSD 9200"),
        oxorany("HyperX ThunderFlash M.2 10000")
    };


	char randomHexChar ( ) {
		return "0123456789abcdef" [ rand ( ) % 16 ];
	}

	char randomHexCharx2 ( ) {
		return "012345678QWERTYUIOPASDFGHJKLZXCVBNM" [ rand ( ) % 16 ];
	}
	ULONG generateRandomIndex ( ULONG max ) {
		LARGE_INTEGER randSeed;
		KeQuerySystemTime ( &randSeed );
		ULONG random = RtlRandomEx ( &randSeed.LowPart ) % max;
		return random;
	}


    char* random_string(char* str, int size)
    {
        if (size == 0) size = (int)strlen(str);
        if (size == 0) return 0;

        const int len = 63;
        const char char_maps[len] = "QWERTYUIOPASDFGHJKLZXCVBNMzxcvbnmasdfghjklqwertyuiop0123456789";

        unsigned long seed = KeQueryTimeIncrement();
        for (int i = 0; i < size; i++)
        {
            unsigned long index = RtlRandomEx(&seed) % len;
            str[i] = char_maps[index];
        }

        return str;
    }

	char* RandomLegitSerials ( char* str , int size )
	{
		if ( size == 0 ) size = ( int ) strlen ( str );
		if ( size == 0 ) return 0;
		for ( int i = 0; i < size; i++ )
		{
			if ( i == 5 || i == 10 || i == 15 || i == 20 ) {
				str [ i ] = '-';
			}
			else {
				str [ i ] = randomHexCharx2 ( );
			}
		}

		return str;
	}



	NTSTATUS convertStringToGUID ( const char* strGUID , GUID& newUUID ) {
		NTSTATUS status = STATUS_SUCCESS;
		unsigned long p0;
		unsigned int p1 , p2;
		unsigned int p3 , p4 , p5 , p6 , p7 , p8 , p9 , p10;
		int fieldsAssigned = sscanf_s ( strGUID , "%8lx-%4hx-%4hx-%2hx%2hx-%2hx%2hx%2hx%2hx%2hx%2hx" ,
			&p0 , &p1 , &p2 , &p3 , &p4 , &p5 , &p6 , &p7 , &p8 , &p9 , &p10 );

		if ( fieldsAssigned == 11 ) {
			newUUID.Data1 = _byteswap_ulong ( p0 );
			newUUID.Data2 = _byteswap_ushort ( ( USHORT ) p1 );
			newUUID.Data3 = _byteswap_ushort ( ( USHORT ) p2 );
			newUUID.Data4 [ 0 ] = ( UCHAR ) p3;
			newUUID.Data4 [ 1 ] = ( UCHAR ) p4;
			newUUID.Data4 [ 2 ] = ( UCHAR ) p5;
			newUUID.Data4 [ 3 ] = ( UCHAR ) p6;
			newUUID.Data4 [ 4 ] = ( UCHAR ) p7;
			newUUID.Data4 [ 5 ] = ( UCHAR ) p8;
			newUUID.Data4 [ 6 ] = ( UCHAR ) p9;
			newUUID.Data4 [ 7 ] = ( UCHAR ) p10;
		}
		else {
			status = STATUS_INVALID_PARAMETER;
		}

		return status;
	}

	void generateRandomGUID ( char* guid ) {
		for ( int i = 0; i < 36; i++ ) {
			if ( i == 8 || i == 13 || i == 18 || i == 23 ) {
				guid [ i ] = '-';
			}
			else {
				guid [ i ] = randomHexChar ( );
			}
		}
		guid [ 36 ] = '\0';
	}

	void generateRandomSerials ( char* guid ) {
		for ( int i = 0; i < 30; i++ ) {
			if ( i == 8 || i == 13 || i == 18 || i == 23 ) {
				guid [ i ] = '-';
			}
			else {
				guid [ i ] = randomHexChar ( );
			}
		}
		guid [ 36 ] = '\0';
	}
}