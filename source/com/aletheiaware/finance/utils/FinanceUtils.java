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
import com.aletheiaware.bc.Channel.RecordCallback;
import com.aletheiaware.bc.Crypto;
import com.aletheiaware.bc.Network;
import com.aletheiaware.bc.utils.BCUtils;
import com.aletheiaware.bc.utils.ChannelUtils;
import com.aletheiaware.finance.FinanceProto.Charge;
import com.aletheiaware.finance.FinanceProto.Invoice;
import com.aletheiaware.finance.FinanceProto.Registration;
import com.aletheiaware.finance.FinanceProto.Subscription;
import com.aletheiaware.finance.FinanceProto.UsageRecord;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

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

    private FinanceUtils() {}

    public static void read(String channel, Cache cache, Network network, String merchantAlias, KeyPair merchantKeys, String customerAlias, KeyPair customerKeys, RecordCallback callback) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
        Reference head = ChannelUtils.getHeadReference(channel, cache, network);
        if (head != null) {
            ByteString bh = head.getBlockHash();
            while (bh != null && !bh.isEmpty()) {
                Block b = ChannelUtils.getBlock(channel, cache, network, bh);
                if (b == null) {
                    break;
                }
                for (BlockEntry e : b.getEntryList()) {
                    Record r = e.getRecord();
                    for (Record.Access a : r.getAccessList()) {
                        KeyPair keys = null;
                        if (merchantKeys != null && a.getAlias().equals(merchantAlias)) {
                            keys = merchantKeys;
                        }
                        if (customerKeys != null && a.getAlias().equals(customerAlias)) {
                            keys = customerKeys;
                        }
                        if (keys != null) {
                            byte[] key = a.getSecretKey().toByteArray();
                            byte[] decryptedKey = Crypto.decryptRSA(keys.getPrivate(), key);
                            byte[] decryptedPayload = Crypto.decryptAES(decryptedKey, r.getPayload().toByteArray());
                            callback.onRecord(bh, b, e, decryptedKey, decryptedPayload);
                        }
                    }
                }
                bh = b.getPrevious();
            }
        }
    }

    public interface RegistrationCallback {
        void onRegistration(BlockEntry entry, Registration registration);
    }

    public static void readRegistration(String channel, Cache cache, Network network, String merchantAlias, KeyPair merchantKeys, String customerAlias, KeyPair customerKeys, RegistrationCallback callback) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
        read(channel, cache, network, merchantAlias, merchantKeys, customerAlias, customerKeys, new RecordCallback() {
            @Override
            public boolean onRecord(ByteString blockHash, Block block, BlockEntry entry, byte[] key, byte[] payload) {
                try {
                    Registration r = Registration.parseFrom(payload);
                    if ((merchantAlias == null || r.getMerchantAlias().equals(merchantAlias)) && (customerAlias == null || r.getCustomerAlias().equals(customerAlias))) {
                        callback.onRegistration(entry, r);
                        return false;
                    }
                } catch (InvalidProtocolBufferException e) {
                    e.printStackTrace();
                }
                return true;
            }
        });
    }

    public interface SubscriptionCallback {
        void onSubscription(BlockEntry entry, Subscription subscription);
    }

    public static void readSubscription(String channel, Cache cache, Network network, String merchantAlias, KeyPair merchantKeys, String customerAlias, KeyPair customerKeys, String productId, String planId, SubscriptionCallback callback) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
        read(channel, cache, network, merchantAlias, merchantKeys, customerAlias, customerKeys, new RecordCallback() {
            @Override
            public boolean onRecord(ByteString blockHash, Block block, BlockEntry entry, byte[] key, byte[] payload) {
                try {
                    Subscription s = Subscription.parseFrom(payload);
                    if ((merchantAlias == null || s.getMerchantAlias().equals(merchantAlias)) && (customerAlias == null || s.getCustomerAlias().equals(customerAlias)) && (productId == null || s.getProductId().equals(productId)) && (planId == null || s.getPlanId().equals(planId))) {
                        callback.onSubscription(entry, s);
                        return false;
                    }
                } catch (InvalidProtocolBufferException e) {
                    e.printStackTrace();
                }
                return true;
            }
        });
    }

    public interface ChargeCallback {
        void onCharge(BlockEntry entry, Charge charge);
    }

    public static void readCharges(String channel, Cache cache, Network network, String merchantAlias, KeyPair merchantKeys, String customerAlias, KeyPair customerKeys, String productId, String planId, ChargeCallback callback) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
        if (callback != null) {
            read(channel, cache, network, merchantAlias, merchantKeys, customerAlias, customerKeys, new RecordCallback() {
                @Override
                public boolean onRecord(ByteString blockHash, Block block, BlockEntry entry, byte[] key, byte[] payload) {
                    try {
                        Charge c = Charge.parseFrom(payload);
                        if ((merchantAlias == null || c.getMerchantAlias().equals(merchantAlias)) && (customerAlias == null || c.getCustomerAlias().equals(customerAlias)) && (productId == null || c.getProductId().equals(productId)) && (planId == null || c.getPlanId().equals(planId))) {
                            callback.onCharge(entry, c);
                        }
                    } catch (InvalidProtocolBufferException e) {
                        e.printStackTrace();
                    }
                    return true;
                }
            });
        }
    }

    public interface InvoiceCallback {
        void onInvoice(BlockEntry entry, Invoice invoice);
    }

    public static void readInvoices(String channel, Cache cache, Network network, String merchantAlias, KeyPair merchantKeys, String customerAlias, KeyPair customerKeys, String productId, String planId, InvoiceCallback callback) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
        if (callback != null) {
            read(channel, cache, network, merchantAlias, merchantKeys, customerAlias, customerKeys, new RecordCallback() {
                @Override
                public boolean onRecord(ByteString blockHash, Block block, BlockEntry entry, byte[] key, byte[] payload) {
                    try {
                        Invoice i = Invoice.parseFrom(payload);
                        if ((merchantAlias == null || i.getMerchantAlias().equals(merchantAlias)) && (customerAlias == null || i.getCustomerAlias().equals(customerAlias)) && (productId == null || i.getProductId().equals(productId)) && (planId == null || i.getPlanId().equals(planId))) {
                            callback.onInvoice(entry, i);
                        }
                    } catch (InvalidProtocolBufferException e) {
                        e.printStackTrace();
                    }
                    return true;
                }
            });
        }
    }

    public interface UsageRecordCallback {
        void onUsageRecord(BlockEntry entry, UsageRecord usageRecord);
    }

    public static void readUsageRecords(String channel, Cache cache, Network network, String merchantAlias, KeyPair merchantKeys, String customerAlias, KeyPair customerKeys, String productId, String planId, UsageRecordCallback callback) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
        if (callback != null) {
            read(channel, cache, network, merchantAlias, merchantKeys, customerAlias, customerKeys, new RecordCallback() {
                @Override
                public boolean onRecord(ByteString blockHash, Block block, BlockEntry entry, byte[] key, byte[] payload) {
                    try {
                        UsageRecord u = UsageRecord.parseFrom(payload);
                        if ((merchantAlias == null || u.getMerchantAlias().equals(merchantAlias)) && (customerAlias == null || u.getCustomerAlias().equals(customerAlias)) && (productId == null || u.getProductId().equals(productId)) && (planId == null || u.getPlanId().equals(planId))) {
                            callback.onUsageRecord(entry, u);
                        }
                    } catch (InvalidProtocolBufferException e) {
                        e.printStackTrace();
                    }
                    return true;
                }
            });
        }
    }
}