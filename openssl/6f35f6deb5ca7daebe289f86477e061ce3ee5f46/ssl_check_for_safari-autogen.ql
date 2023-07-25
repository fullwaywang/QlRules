/**
 * @name openssl-6f35f6deb5ca7daebe289f86477e061ce3ee5f46-ssl_check_for_safari
 * @id cpp/openssl/6f35f6deb5ca7daebe289f86477e061ce3ee5f46/ssl-check-for-safari
 * @description openssl-6f35f6deb5ca7daebe289f86477e061ce3ee5f46-ssl/t1_lib.c-ssl_check_for_safari CVE-2016-2177
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlimit_916, Parameter vdata_915, ReturnStmt target_27, RelationalOperation target_23, ExprStmt target_28) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vlimit_916
		and target_0.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vdata_915
		and target_0.getGreaterOperand() instanceof Literal
		and target_0.getParent().(IfStmt).getThen()=target_27
		and target_0.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_23.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_28.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vlimit_916, Parameter vdata_915, ReturnStmt target_29, RelationalOperation target_22, RelationalOperation target_24, ExprStmt target_28, ExprStmt target_30) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vlimit_916
		and target_1.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vdata_915
		and target_1.getGreaterOperand() instanceof Literal
		and target_1.getParent().(IfStmt).getThen()=target_29
		and target_22.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_1.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_24.getLesserOperand().(VariableAccess).getLocation())
		and target_28.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation())
		and target_1.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_30.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vlimit_916, Variable vsize_918, Parameter vdata_915, ReturnStmt target_31, RelationalOperation target_23, EqualityOperation target_32, ExprStmt target_33, ExprStmt target_34) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vlimit_916
		and target_2.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vdata_915
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vsize_918
		and target_2.getParent().(IfStmt).getThen()=target_31
		and target_23.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_2.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_2.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_32.getAnOperand().(VariableAccess).getLocation())
		and target_33.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(VariableAccess).getLocation())
		and target_2.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_34.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vlimit_916, Parameter vdata_915, ReturnStmt target_35, RelationalOperation target_24, EqualityOperation target_36, ExprStmt target_34, EqualityOperation target_37) {
	exists(PointerArithmeticOperation target_3 |
		target_3.getLeftOperand().(VariableAccess).getTarget()=vlimit_916
		and target_3.getRightOperand().(VariableAccess).getTarget()=vdata_915
		and target_3.getParent().(NEExpr).getAnOperand() instanceof PointerArithmeticOperation
		and target_3.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vlimit_916
		and target_3.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_35
		and target_24.getLesserOperand().(VariableAccess).getLocation().isBefore(target_3.getLeftOperand().(VariableAccess).getLocation())
		and target_3.getLeftOperand().(VariableAccess).getLocation().isBefore(target_36.getAnOperand().(VariableAccess).getLocation())
		and target_34.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getRightOperand().(VariableAccess).getLocation())
		and target_3.getRightOperand().(VariableAccess).getLocation().isBefore(target_37.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Parameter vlimit_916, ReturnStmt target_35) {
	exists(AddExpr target_4 |
		target_4.getValue()="34"
		and target_4.getParent().(NEExpr).getAnOperand() instanceof PointerArithmeticOperation
		and target_4.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vlimit_916
		and target_4.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_35)
}

predicate func_5(Parameter vlimit_916, Parameter vdata_915, ReturnStmt target_38, EqualityOperation target_32, PointerArithmeticOperation target_39, EqualityOperation target_40) {
	exists(PointerArithmeticOperation target_5 |
		target_5.getLeftOperand().(VariableAccess).getTarget()=vlimit_916
		and target_5.getRightOperand().(VariableAccess).getTarget()=vdata_915
		and target_5.getParent().(NEExpr).getAnOperand() instanceof PointerArithmeticOperation
		and target_5.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vlimit_916
		and target_5.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_38
		and target_32.getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getLeftOperand().(VariableAccess).getLocation())
		and target_39.getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getRightOperand().(VariableAccess).getLocation())
		and target_5.getRightOperand().(VariableAccess).getLocation().isBefore(target_40.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_6(Parameter vlimit_916, VariableAccess target_6) {
		target_6.getTarget()=vlimit_916
}

predicate func_7(Parameter vlimit_916, VariableAccess target_7) {
		target_7.getTarget()=vlimit_916
}

predicate func_8(Variable vlen2_963, VariableAccess target_8) {
		target_8.getTarget()=vlen2_963
}

predicate func_9(Variable vlen_972, VariableAccess target_9) {
		target_9.getTarget()=vlen_972
}

predicate func_10(Parameter vdata_915, ReturnStmt target_27, VariableAccess target_10) {
		target_10.getTarget()=vdata_915
		and target_10.getParent().(GEExpr).getLesserOperand() instanceof PointerArithmeticOperation
		and target_10.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_27
}

predicate func_12(Parameter vdata_915, ReturnStmt target_29, VariableAccess target_12) {
		target_12.getTarget()=vdata_915
		and target_12.getParent().(GTExpr).getLesserOperand() instanceof PointerArithmeticOperation
		and target_12.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_29
}

predicate func_14(Parameter vdata_915, VariableAccess target_14) {
		target_14.getTarget()=vdata_915
}

predicate func_15(Variable vsize_918, VariableAccess target_15) {
		target_15.getTarget()=vsize_918
}

predicate func_16(Parameter vlimit_916, ReturnStmt target_31, VariableAccess target_16) {
		target_16.getTarget()=vlimit_916
		and target_16.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_16.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_31
}

predicate func_17(Parameter vdata_915, VariableAccess target_17) {
		target_17.getTarget()=vdata_915
}

predicate func_18(Variable vlen1_962, VariableAccess target_18) {
		target_18.getTarget()=vlen1_962
}

predicate func_19(Parameter vlimit_916, ReturnStmt target_35, VariableAccess target_19) {
		target_19.getTarget()=vlimit_916
		and target_19.getParent().(NEExpr).getAnOperand() instanceof PointerArithmeticOperation
		and target_19.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_35
}

predicate func_20(Parameter vdata_915, VariableAccess target_20) {
		target_20.getTarget()=vdata_915
}

predicate func_21(Parameter vlimit_916, ReturnStmt target_38, VariableAccess target_21) {
		target_21.getTarget()=vlimit_916
		and target_21.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_38
}

predicate func_22(Parameter vlimit_916, Parameter vdata_915, ReturnStmt target_27, RelationalOperation target_22) {
		 (target_22 instanceof GEExpr or target_22 instanceof LEExpr)
		and target_22.getGreaterOperand().(VariableAccess).getTarget()=vdata_915
		and target_22.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vlimit_916
		and target_22.getLesserOperand().(PointerArithmeticOperation).getRightOperand() instanceof Literal
		and target_22.getParent().(IfStmt).getThen()=target_27
}

predicate func_23(Parameter vlimit_916, Parameter vdata_915, ReturnStmt target_29, RelationalOperation target_23) {
		 (target_23 instanceof GTExpr or target_23 instanceof LTExpr)
		and target_23.getGreaterOperand().(VariableAccess).getTarget()=vdata_915
		and target_23.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vlimit_916
		and target_23.getLesserOperand().(PointerArithmeticOperation).getRightOperand() instanceof Literal
		and target_23.getParent().(IfStmt).getThen()=target_29
}

predicate func_24(Parameter vlimit_916, Variable vsize_918, Parameter vdata_915, ReturnStmt target_31, RelationalOperation target_24) {
		 (target_24 instanceof GTExpr or target_24 instanceof LTExpr)
		and target_24.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_915
		and target_24.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsize_918
		and target_24.getLesserOperand().(VariableAccess).getTarget()=vlimit_916
		and target_24.getParent().(IfStmt).getThen()=target_31
}

predicate func_25(Parameter vlimit_916, Variable vlen1_962, Variable vlen2_963, Parameter vdata_915, ReturnStmt target_35, PointerArithmeticOperation target_25) {
		target_25.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_915
		and target_25.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlen1_962
		and target_25.getAnOperand().(VariableAccess).getTarget()=vlen2_963
		and target_25.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vlimit_916
		and target_25.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_35
}

predicate func_26(Parameter vlimit_916, Variable vlen_972, Parameter vdata_915, ReturnStmt target_38, PointerArithmeticOperation target_26) {
		target_26.getAnOperand().(VariableAccess).getTarget()=vdata_915
		and target_26.getAnOperand().(VariableAccess).getTarget()=vlen_972
		and target_26.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vlimit_916
		and target_26.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_38
}

predicate func_27(ReturnStmt target_27) {
		target_27.toString() = "return ..."
}

predicate func_28(Parameter vdata_915, ExprStmt target_28) {
		target_28.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata_915
		and target_28.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_29(ReturnStmt target_29) {
		target_29.toString() = "return ..."
}

predicate func_30(Parameter vdata_915, ExprStmt target_30) {
		target_30.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_915
		and target_30.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_30.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_30.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_915
		and target_30.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_30.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata_915
		and target_30.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_31(ReturnStmt target_31) {
		target_31.toString() = "return ..."
}

predicate func_32(Parameter vlimit_916, EqualityOperation target_32) {
		target_32.getAnOperand() instanceof PointerArithmeticOperation
		and target_32.getAnOperand().(VariableAccess).getTarget()=vlimit_916
}

predicate func_33(Variable vsize_918, Parameter vdata_915, ExprStmt target_33) {
		target_33.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_918
		and target_33.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_915
		and target_33.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_33.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_33.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_915
		and target_33.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_33.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata_915
		and target_33.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_34(Variable vsize_918, Parameter vdata_915, ExprStmt target_34) {
		target_34.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata_915
		and target_34.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vsize_918
}

predicate func_35(ReturnStmt target_35) {
		target_35.toString() = "return ..."
}

predicate func_36(Parameter vlimit_916, EqualityOperation target_36) {
		target_36.getAnOperand() instanceof PointerArithmeticOperation
		and target_36.getAnOperand().(VariableAccess).getTarget()=vlimit_916
}

predicate func_37(Variable vlen1_962, Parameter vdata_915, EqualityOperation target_37) {
		target_37.getAnOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_37.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_915
		and target_37.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen1_962
		and target_37.getAnOperand().(Literal).getValue()="0"
}

predicate func_38(ReturnStmt target_38) {
		target_38.toString() = "return ..."
}

predicate func_39(Variable vlen1_962, Parameter vdata_915, PointerArithmeticOperation target_39) {
		target_39.getAnOperand().(VariableAccess).getTarget()=vdata_915
		and target_39.getAnOperand().(VariableAccess).getTarget()=vlen1_962
}

predicate func_40(Variable vlen_972, Parameter vdata_915, EqualityOperation target_40) {
		target_40.getAnOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_40.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_915
		and target_40.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_972
		and target_40.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vlimit_916, Variable vsize_918, Variable vlen1_962, Variable vlen2_963, Variable vlen_972, Parameter vdata_915, VariableAccess target_6, VariableAccess target_7, VariableAccess target_8, VariableAccess target_9, VariableAccess target_10, VariableAccess target_12, VariableAccess target_14, VariableAccess target_15, VariableAccess target_16, VariableAccess target_17, VariableAccess target_18, VariableAccess target_19, VariableAccess target_20, VariableAccess target_21, RelationalOperation target_22, RelationalOperation target_23, RelationalOperation target_24, PointerArithmeticOperation target_25, PointerArithmeticOperation target_26, ReturnStmt target_27, ExprStmt target_28, ReturnStmt target_29, ExprStmt target_30, ReturnStmt target_31, EqualityOperation target_32, ExprStmt target_33, ExprStmt target_34, ReturnStmt target_35, EqualityOperation target_36, EqualityOperation target_37, ReturnStmt target_38, PointerArithmeticOperation target_39, EqualityOperation target_40
where
not func_0(vlimit_916, vdata_915, target_27, target_23, target_28)
and not func_1(vlimit_916, vdata_915, target_29, target_22, target_24, target_28, target_30)
and not func_2(vlimit_916, vsize_918, vdata_915, target_31, target_23, target_32, target_33, target_34)
and not func_3(vlimit_916, vdata_915, target_35, target_24, target_36, target_34, target_37)
and not func_4(vlimit_916, target_35)
and not func_5(vlimit_916, vdata_915, target_38, target_32, target_39, target_40)
and func_6(vlimit_916, target_6)
and func_7(vlimit_916, target_7)
and func_8(vlen2_963, target_8)
and func_9(vlen_972, target_9)
and func_10(vdata_915, target_27, target_10)
and func_12(vdata_915, target_29, target_12)
and func_14(vdata_915, target_14)
and func_15(vsize_918, target_15)
and func_16(vlimit_916, target_31, target_16)
and func_17(vdata_915, target_17)
and func_18(vlen1_962, target_18)
and func_19(vlimit_916, target_35, target_19)
and func_20(vdata_915, target_20)
and func_21(vlimit_916, target_38, target_21)
and func_22(vlimit_916, vdata_915, target_27, target_22)
and func_23(vlimit_916, vdata_915, target_29, target_23)
and func_24(vlimit_916, vsize_918, vdata_915, target_31, target_24)
and func_25(vlimit_916, vlen1_962, vlen2_963, vdata_915, target_35, target_25)
and func_26(vlimit_916, vlen_972, vdata_915, target_38, target_26)
and func_27(target_27)
and func_28(vdata_915, target_28)
and func_29(target_29)
and func_30(vdata_915, target_30)
and func_31(target_31)
and func_32(vlimit_916, target_32)
and func_33(vsize_918, vdata_915, target_33)
and func_34(vsize_918, vdata_915, target_34)
and func_35(target_35)
and func_36(vlimit_916, target_36)
and func_37(vlen1_962, vdata_915, target_37)
and func_38(target_38)
and func_39(vlen1_962, vdata_915, target_39)
and func_40(vlen_972, vdata_915, target_40)
and vlimit_916.getType().hasName("const unsigned char *")
and vsize_918.getType().hasName("unsigned short")
and vlen1_962.getType().hasName("const size_t")
and vlen2_963.getType().hasName("const size_t")
and vlen_972.getType().hasName("const size_t")
and vdata_915.getType().hasName("const unsigned char *")
and vlimit_916.getParentScope+() = func
and vsize_918.getParentScope+() = func
and vlen1_962.getParentScope+() = func
and vlen2_963.getParentScope+() = func
and vlen_972.getParentScope+() = func
and vdata_915.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
