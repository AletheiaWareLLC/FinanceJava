/*
 * Copyright 2019 Aletheia Ware LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.aletheiaware.finance.utils;

import com.aletheiaware.bc.BCProto.Block;
import com.aletheiaware.bc.BCProto.BlockEntry;
import com.aletheiaware.bc.BCProto.Record;
import com.aletheiaware.bc.BCProto.Reference;
import com.aletheiaware.bc.Cache;
import com.aletheiaware.bc.Crypto;
import com.aletheiaware.bc.Network;
import com.aletheiaware.bc.utils.BCUtils;
import com.aletheiaware.bc.utils.ChannelUtils;
import com.aletheiaware.finance.FinanceProto.Customer;
import com.aletheiaware.finance.FinanceProto.Subscription;

import com.google.protobuf.ByteString;

import java.io.IOException;
import java.net.InetAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public final class FinanceUtils {

    public static final String CHARGE_CHANNEL = "Charge";
    public static final String CUSTOMER_CHANNEL = "Customer";
    public static final String SUBSCRIPTION_CHANNEL = "Subscription";
    public static final String USAGE_RECORD_CHANNEL = "UsageRecord";

    private FinanceUtils() {}

    public static String getCustomerId(Cache cache, Network network, String alias, KeyPair keys) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
        Reference head = ChannelUtils.getHeadReference(CUSTOMER_CHANNEL, cache, network);
        if (head != null) {
            ByteString bh = head.getBlockHash();
            while (bh != null && !bh.isEmpty()) {
                Block b = ChannelUtils.getBlock(CUSTOMER_CHANNEL, cache, network, bh);
                if (b == null) {
                    break;
                }
                for (BlockEntry e : b.getEntryList()) {
                    Record r = e.getRecord();
                    for (Record.Access a : r.getAccessList()) {
                        if (a.getAlias().equals(alias)) {
                            byte[] key = a.getSecretKey().toByteArray();
                            byte[] decryptedKey = Crypto.decryptRSA(keys.getPrivate(), key);
                            byte[] decryptedPayload = Crypto.decryptAES(decryptedKey, r.getPayload().toByteArray());
                            return Customer.parseFrom(decryptedPayload).getCustomerId();
                        }
                    }
                }
                bh = b.getPrevious();
            }
        }
        return null;
    }

    public static String getSubscriptionId(Cache cache, Network network, String alias, KeyPair keys) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
        Reference head = ChannelUtils.getHeadReference(SUBSCRIPTION_CHANNEL, cache, network);
        if (head != null) {
            ByteString bh = head.getBlockHash();
            while (bh != null && !bh.isEmpty()) {
                Block b = ChannelUtils.getBlock(SUBSCRIPTION_CHANNEL, cache, network, bh);
                if (b == null) {
                    break;
                }
                for (BlockEntry e : b.getEntryList()) {
                    Record r = e.getRecord();
                    for (Record.Access a : r.getAccessList()) {
                        if (a.getAlias().equals(alias)) {
                            byte[] key = a.getSecretKey().toByteArray();
                            byte[] decryptedKey = Crypto.decryptRSA(keys.getPrivate(), key);
                            byte[] decryptedPayload = Crypto.decryptAES(decryptedKey, r.getPayload().toByteArray());
                            return Subscription.parseFrom(decryptedPayload).getSubscriptionId();
                        }
                    }
                }
                bh = b.getPrevious();
            }
        }
        return null;
    }
}