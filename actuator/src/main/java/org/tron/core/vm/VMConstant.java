package org.tron.core.vm;

public class VMConstant {

  public static final int CONTRACT_NAME_LENGTH = 32;
  public static final int MIN_TOKEN_ID = 1_000_000;
  public static final int SIG_LENGTH = 65;
  // Permission IDs: 0=owner, 1=witness, 2-9=active (up to 8 active permissions)
  public static final int MAX_PERMISSION_ID = 9;

  // Numbers
  public static final int ONE_HUNDRED = 100;
  public static final int ONE_THOUSAND = 1000;
  public static final long SUN_PER_ENERGY = 100;

  public static final String WITHDRAW_EXPIRE_BALANCE = "WithdrawExpireBalance";

  private VMConstant() {
  }
}
