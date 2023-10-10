/**
 * @name openssl-a004e72b95835136d3f1ea90517f706c24c03da7-ssl_scan_clienthello_custom_tlsext
 * @id cpp/openssl/a004e72b95835136d3f1ea90517f706c24c03da7/ssl-scan-clienthello-custom-tlsext
 * @description openssl-a004e72b95835136d3f1ea90517f706c24c03da7-ssl/t1_lib.c-ssl_scan_clienthello_custom_tlsext CVE-2016-2177
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_2466, Parameter vlimit_2467, ExprStmt target_20, RelationalOperation target_17) {
	exists(PointerArithmeticOperation target_0 |
		target_0.getLeftOperand().(VariableAccess).getTarget()=vlimit_2467
		and target_0.getRightOperand().(VariableAccess).getTarget()=vdata_2466
		and target_0.getParent().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=vdata_2466
		and target_0.getParent().(LEExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_0.getRightOperand().(VariableAccess).getLocation().isBefore(target_20.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_0.getLeftOperand().(VariableAccess).getLocation().isBefore(target_17.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vdata_2466, Parameter vlimit_2467, Variable vlen_2470, ReturnStmt target_21, ExprStmt target_20, RelationalOperation target_22) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vlimit_2467
		and target_1.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vdata_2466
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vlen_2470
		and target_1.getParent().(IfStmt).getThen()=target_21
		and target_20.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation())
		and target_1.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_22.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vdata_2466, Parameter vlimit_2467, ReturnStmt target_24, RelationalOperation target_17, ExprStmt target_25, RelationalOperation target_19) {
	exists(PointerArithmeticOperation target_2 |
		target_2.getLeftOperand().(VariableAccess).getTarget()=vlimit_2467
		and target_2.getRightOperand().(VariableAccess).getTarget()=vdata_2466
		and target_2.getParent().(GEExpr).getGreaterOperand().(VariableAccess).getTarget()=vdata_2466
		and target_2.getParent().(GEExpr).getLesserOperand() instanceof PointerArithmeticOperation
		and target_2.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_24
		and target_17.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getRightOperand().(VariableAccess).getLocation())
		and target_2.getRightOperand().(VariableAccess).getLocation().isBefore(target_25.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_2.getLeftOperand().(VariableAccess).getLocation().isBefore(target_19.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vdata_2466, Parameter vlimit_2467, Variable vsize_2470, ReturnStmt target_26, ExprStmt target_27, RelationalOperation target_28, RelationalOperation target_22) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vlimit_2467
		and target_3.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vdata_2466
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vsize_2470
		and target_3.getParent().(IfStmt).getThen()=target_26
		and target_27.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_3.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation())
		and target_3.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_28.getLesserOperand().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_4(Parameter vlimit_2467, VariableAccess target_4) {
		target_4.getTarget()=vlimit_2467
}

predicate func_5(Parameter vlimit_2467, VariableAccess target_5) {
		target_5.getTarget()=vlimit_2467
}

predicate func_6(Parameter vlimit_2467, VariableAccess target_6) {
		target_6.getTarget()=vlimit_2467
}

predicate func_7(Parameter vdata_2466, ReturnStmt target_24, VariableAccess target_7) {
		target_7.getTarget()=vdata_2466
		and target_7.getParent().(GEExpr).getLesserOperand() instanceof PointerArithmeticOperation
		and target_7.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_24
}

predicate func_9(Parameter vdata_2466, ReturnStmt target_21, VariableAccess target_9) {
		target_9.getTarget()=vdata_2466
		and target_9.getParent().(GTExpr).getLesserOperand() instanceof PointerArithmeticOperation
		and target_9.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_21
}

predicate func_10(Variable vlen_2470, VariableAccess target_10) {
		target_10.getTarget()=vlen_2470
}

predicate func_11(Parameter vdata_2466, VariableAccess target_11) {
		target_11.getTarget()=vdata_2466
		and target_11.getParent().(LEExpr).getGreaterOperand() instanceof PointerArithmeticOperation
}

predicate func_13(Parameter vdata_2466, VariableAccess target_13) {
		target_13.getTarget()=vdata_2466
}

predicate func_14(Variable vsize_2470, VariableAccess target_14) {
		target_14.getTarget()=vsize_2470
}

predicate func_15(Parameter vlimit_2467, ReturnStmt target_26, VariableAccess target_15) {
		target_15.getTarget()=vlimit_2467
		and target_15.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_15.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_26
}

predicate func_16(Parameter vlimit_2467, ReturnStmt target_24, PointerArithmeticOperation target_16) {
		target_16.getLeftOperand().(VariableAccess).getTarget()=vlimit_2467
		and target_16.getRightOperand() instanceof Literal
		and target_16.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_24
}

predicate func_17(Parameter vdata_2466, Parameter vlimit_2467, Variable vlen_2470, ReturnStmt target_21, RelationalOperation target_17) {
		 (target_17 instanceof GTExpr or target_17 instanceof LTExpr)
		and target_17.getGreaterOperand().(VariableAccess).getTarget()=vdata_2466
		and target_17.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vlimit_2467
		and target_17.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vlen_2470
		and target_17.getParent().(IfStmt).getThen()=target_21
}

predicate func_18(Parameter vlimit_2467, PointerArithmeticOperation target_18) {
		target_18.getLeftOperand().(VariableAccess).getTarget()=vlimit_2467
		and target_18.getRightOperand() instanceof Literal
}

predicate func_19(Parameter vdata_2466, Parameter vlimit_2467, Variable vsize_2470, ReturnStmt target_26, RelationalOperation target_19) {
		 (target_19 instanceof GTExpr or target_19 instanceof LTExpr)
		and target_19.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_2466
		and target_19.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsize_2470
		and target_19.getLesserOperand().(VariableAccess).getTarget()=vlimit_2467
		and target_19.getParent().(IfStmt).getThen()=target_26
}

predicate func_20(Parameter vdata_2466, Variable vlen_2470, ExprStmt target_20) {
		target_20.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_2470
		and target_20.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_2466
		and target_20.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_20.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_20.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_2466
		and target_20.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_20.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata_2466
		and target_20.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_21(ReturnStmt target_21) {
		target_21.getExpr().(Literal).getValue()="1"
}

predicate func_22(Parameter vdata_2466, RelationalOperation target_22) {
		 (target_22 instanceof GEExpr or target_22 instanceof LEExpr)
		and target_22.getLesserOperand().(VariableAccess).getTarget()=vdata_2466
		and target_22.getGreaterOperand() instanceof PointerArithmeticOperation
}

predicate func_24(ReturnStmt target_24) {
		target_24.getExpr().(Literal).getValue()="1"
}

predicate func_25(Parameter vdata_2466, ExprStmt target_25) {
		target_25.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_2466
		and target_25.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_25.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_25.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_2466
		and target_25.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_25.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata_2466
		and target_25.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_26(ReturnStmt target_26) {
		target_26.getExpr().(Literal).getValue()="1"
}

predicate func_27(Parameter vdata_2466, Variable vsize_2470, ExprStmt target_27) {
		target_27.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_2470
		and target_27.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_2466
		and target_27.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_27.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_27.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_2466
		and target_27.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_27.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata_2466
		and target_27.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_28(Parameter vdata_2466, Variable vsize_2470, RelationalOperation target_28) {
		 (target_28 instanceof GEExpr or target_28 instanceof LEExpr)
		and target_28.getLesserOperand().(FunctionCall).getTarget().hasName("custom_ext_parse")
		and target_28.getLesserOperand().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_28.getLesserOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdata_2466
		and target_28.getLesserOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsize_2470
		and target_28.getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Parameter vdata_2466, Parameter vlimit_2467, Variable vsize_2470, Variable vlen_2470, VariableAccess target_4, VariableAccess target_5, VariableAccess target_6, VariableAccess target_7, VariableAccess target_9, VariableAccess target_10, VariableAccess target_11, VariableAccess target_13, VariableAccess target_14, VariableAccess target_15, PointerArithmeticOperation target_16, RelationalOperation target_17, PointerArithmeticOperation target_18, RelationalOperation target_19, ExprStmt target_20, ReturnStmt target_21, RelationalOperation target_22, ReturnStmt target_24, ExprStmt target_25, ReturnStmt target_26, ExprStmt target_27, RelationalOperation target_28
where
not func_0(vdata_2466, vlimit_2467, target_20, target_17)
and not func_1(vdata_2466, vlimit_2467, vlen_2470, target_21, target_20, target_22)
and not func_2(vdata_2466, vlimit_2467, target_24, target_17, target_25, target_19)
and not func_3(vdata_2466, vlimit_2467, vsize_2470, target_26, target_27, target_28, target_22)
and func_4(vlimit_2467, target_4)
and func_5(vlimit_2467, target_5)
and func_6(vlimit_2467, target_6)
and func_7(vdata_2466, target_24, target_7)
and func_9(vdata_2466, target_21, target_9)
and func_10(vlen_2470, target_10)
and func_11(vdata_2466, target_11)
and func_13(vdata_2466, target_13)
and func_14(vsize_2470, target_14)
and func_15(vlimit_2467, target_26, target_15)
and func_16(vlimit_2467, target_24, target_16)
and func_17(vdata_2466, vlimit_2467, vlen_2470, target_21, target_17)
and func_18(vlimit_2467, target_18)
and func_19(vdata_2466, vlimit_2467, vsize_2470, target_26, target_19)
and func_20(vdata_2466, vlen_2470, target_20)
and func_21(target_21)
and func_22(vdata_2466, target_22)
and func_24(target_24)
and func_25(vdata_2466, target_25)
and func_26(target_26)
and func_27(vdata_2466, vsize_2470, target_27)
and func_28(vdata_2466, vsize_2470, target_28)
and vdata_2466.getType().hasName("const unsigned char *")
and vlimit_2467.getType().hasName("const unsigned char *")
and vsize_2470.getType().hasName("unsigned short")
and vlen_2470.getType().hasName("unsigned short")
and vdata_2466.getParentScope+() = func
and vlimit_2467.getParentScope+() = func
and vsize_2470.getParentScope+() = func
and vlen_2470.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
