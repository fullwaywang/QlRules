/**
 * @name openssl-a004e72b95835136d3f1ea90517f706c24c03da7-ssl_scan_serverhello_tlsext
 * @id cpp/openssl/a004e72b95835136d3f1ea90517f706c24c03da7/ssl-scan-serverhello-tlsext
 * @description openssl-a004e72b95835136d3f1ea90517f706c24c03da7-ssl/t1_lib.c-ssl_scan_serverhello_tlsext CVE-2016-2177
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdata_2554, ExprStmt target_21) {
	exists(PointerArithmeticOperation target_0 |
		target_0.getLeftOperand() instanceof PointerArithmeticOperation
		and target_0.getRightOperand().(VariableAccess).getTarget()=vdata_2554
		and target_0.getParent().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=vdata_2554
		and target_0.getParent().(LEExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_0.getRightOperand().(VariableAccess).getLocation().isBefore(target_21.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_1(Variable vlength_2551, Variable vdata_2554, BlockStmt target_22, ExprStmt target_21, RelationalOperation target_23) {
	exists(PointerArithmeticOperation target_1 |
		target_1.getLeftOperand() instanceof PointerArithmeticOperation
		and target_1.getRightOperand().(VariableAccess).getTarget()=vdata_2554
		and target_1.getParent().(NEExpr).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_2554
		and target_1.getParent().(NEExpr).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlength_2551
		and target_1.getParent().(NEExpr).getAnOperand() instanceof PointerArithmeticOperation
		and target_1.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_22
		and target_21.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_1.getRightOperand().(VariableAccess).getLocation())
		and target_1.getRightOperand().(VariableAccess).getLocation().isBefore(target_23.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vdata_2554, GotoStmt target_24, EqualityOperation target_25, ExprStmt target_26) {
	exists(PointerArithmeticOperation target_2 |
		target_2.getLeftOperand() instanceof PointerArithmeticOperation
		and target_2.getRightOperand().(VariableAccess).getTarget()=vdata_2554
		and target_2.getParent().(GEExpr).getGreaterOperand().(VariableAccess).getTarget()=vdata_2554
		and target_2.getParent().(GEExpr).getLesserOperand() instanceof PointerArithmeticOperation
		and target_2.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_24
		and target_25.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getRightOperand().(VariableAccess).getLocation())
		and target_2.getRightOperand().(VariableAccess).getLocation().isBefore(target_26.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vn_2549, Variable vsize_2553, Variable vdata_2554, Parameter vd_2549, GotoStmt target_27, EqualityOperation target_25, ExprStmt target_29, ExprStmt target_30) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vd_2549
		and target_3.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vn_2549
		and target_3.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vdata_2554
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vsize_2553
		and target_3.getParent().(IfStmt).getThen()=target_27
		and target_29.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getGreaterOperand().(VariableAccess).getLocation())
		and target_3.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_30.getExpr().(VariableCall).getArgument(4).(VariableAccess).getLocation()))
}

predicate func_6(Parameter vn_2549, Parameter vd_2549, BlockStmt target_22, PointerArithmeticOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vd_2549
		and target_6.getAnOperand().(VariableAccess).getTarget()=vn_2549
		and target_6.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_22
}

predicate func_7(Parameter vn_2549, Parameter vd_2549, PointerArithmeticOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vd_2549
		and target_7.getAnOperand().(VariableAccess).getTarget()=vn_2549
}

predicate func_8(Parameter vn_2549, Parameter vd_2549, PointerArithmeticOperation target_8) {
		target_8.getAnOperand().(VariableAccess).getTarget()=vd_2549
		and target_8.getAnOperand().(VariableAccess).getTarget()=vn_2549
}

predicate func_9(Parameter vn_2549, Parameter vd_2549, GotoStmt target_27, PointerArithmeticOperation target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vd_2549
		and target_9.getAnOperand().(VariableAccess).getTarget()=vn_2549
		and target_9.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_9.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_27
}

predicate func_10(Variable vlength_2551, VariableAccess target_10) {
		target_10.getTarget()=vlength_2551
}

predicate func_11(Variable vdata_2554, GotoStmt target_24, VariableAccess target_11) {
		target_11.getTarget()=vdata_2554
		and target_11.getParent().(GEExpr).getLesserOperand() instanceof PointerArithmeticOperation
		and target_11.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_24
}

predicate func_13(Variable vdata_2554, VariableAccess target_13) {
		target_13.getTarget()=vdata_2554
}

predicate func_14(Variable vdata_2554, VariableAccess target_14) {
		target_14.getTarget()=vdata_2554
		and target_14.getParent().(LEExpr).getGreaterOperand() instanceof PointerArithmeticOperation
}

predicate func_16(Variable vdata_2554, VariableAccess target_16) {
		target_16.getTarget()=vdata_2554
}

predicate func_17(Variable vsize_2553, VariableAccess target_17) {
		target_17.getTarget()=vsize_2553
}

predicate func_18(GotoStmt target_24, Function func, PointerArithmeticOperation target_18) {
		target_18.getLeftOperand() instanceof PointerArithmeticOperation
		and target_18.getRightOperand() instanceof Literal
		and target_18.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_24
		and target_18.getEnclosingFunction() = func
}

predicate func_19(Function func, PointerArithmeticOperation target_19) {
		target_19.getLeftOperand() instanceof PointerArithmeticOperation
		and target_19.getRightOperand() instanceof Literal
		and target_19.getEnclosingFunction() = func
}

predicate func_20(Variable vsize_2553, Variable vdata_2554, GotoStmt target_27, RelationalOperation target_20) {
		 (target_20 instanceof GTExpr or target_20 instanceof LTExpr)
		and target_20.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_2554
		and target_20.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsize_2553
		and target_20.getLesserOperand() instanceof PointerArithmeticOperation
		and target_20.getParent().(IfStmt).getThen()=target_27
}

predicate func_21(Variable vlength_2551, Variable vdata_2554, ExprStmt target_21) {
		target_21.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlength_2551
		and target_21.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_2554
		and target_21.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_21.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_21.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_2554
		and target_21.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_21.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata_2554
		and target_21.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_22(BlockStmt target_22) {
		target_22.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_22.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_23(Variable vdata_2554, RelationalOperation target_23) {
		 (target_23 instanceof GEExpr or target_23 instanceof LEExpr)
		and target_23.getLesserOperand().(VariableAccess).getTarget()=vdata_2554
		and target_23.getGreaterOperand() instanceof PointerArithmeticOperation
}

predicate func_24(GotoStmt target_24) {
		target_24.toString() = "goto ..."
		and target_24.getName() ="ri_check"
}

predicate func_25(Variable vlength_2551, Variable vdata_2554, EqualityOperation target_25) {
		target_25.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_2554
		and target_25.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlength_2551
		and target_25.getAnOperand() instanceof PointerArithmeticOperation
}

predicate func_26(Variable vdata_2554, ExprStmt target_26) {
		target_26.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_2554
		and target_26.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_26.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_26.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_2554
		and target_26.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_26.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata_2554
		and target_26.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_27(GotoStmt target_27) {
		target_27.toString() = "goto ..."
		and target_27.getName() ="ri_check"
}

predicate func_29(Variable vsize_2553, Variable vdata_2554, ExprStmt target_29) {
		target_29.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_2553
		and target_29.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_2554
		and target_29.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_29.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_29.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_2554
		and target_29.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_29.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata_2554
		and target_29.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_30(Variable vsize_2553, Variable vdata_2554, ExprStmt target_30) {
		target_30.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="tlsext_debug_cb"
		and target_30.getExpr().(VariableCall).getArgument(1).(Literal).getValue()="1"
		and target_30.getExpr().(VariableCall).getArgument(3).(VariableAccess).getTarget()=vdata_2554
		and target_30.getExpr().(VariableCall).getArgument(4).(VariableAccess).getTarget()=vsize_2553
		and target_30.getExpr().(VariableCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="tlsext_debug_arg"
}

from Function func, Parameter vn_2549, Variable vlength_2551, Variable vsize_2553, Variable vdata_2554, Parameter vd_2549, PointerArithmeticOperation target_6, PointerArithmeticOperation target_7, PointerArithmeticOperation target_8, PointerArithmeticOperation target_9, VariableAccess target_10, VariableAccess target_11, VariableAccess target_13, VariableAccess target_14, VariableAccess target_16, VariableAccess target_17, PointerArithmeticOperation target_18, PointerArithmeticOperation target_19, RelationalOperation target_20, ExprStmt target_21, BlockStmt target_22, RelationalOperation target_23, GotoStmt target_24, EqualityOperation target_25, ExprStmt target_26, GotoStmt target_27, ExprStmt target_29, ExprStmt target_30
where
not func_0(vdata_2554, target_21)
and not func_1(vlength_2551, vdata_2554, target_22, target_21, target_23)
and not func_2(vdata_2554, target_24, target_25, target_26)
and not func_3(vn_2549, vsize_2553, vdata_2554, vd_2549, target_27, target_25, target_29, target_30)
and func_6(vn_2549, vd_2549, target_22, target_6)
and func_7(vn_2549, vd_2549, target_7)
and func_8(vn_2549, vd_2549, target_8)
and func_9(vn_2549, vd_2549, target_27, target_9)
and func_10(vlength_2551, target_10)
and func_11(vdata_2554, target_24, target_11)
and func_13(vdata_2554, target_13)
and func_14(vdata_2554, target_14)
and func_16(vdata_2554, target_16)
and func_17(vsize_2553, target_17)
and func_18(target_24, func, target_18)
and func_19(func, target_19)
and func_20(vsize_2553, vdata_2554, target_27, target_20)
and func_21(vlength_2551, vdata_2554, target_21)
and func_22(target_22)
and func_23(vdata_2554, target_23)
and func_24(target_24)
and func_25(vlength_2551, vdata_2554, target_25)
and func_26(vdata_2554, target_26)
and func_27(target_27)
and func_29(vsize_2553, vdata_2554, target_29)
and func_30(vsize_2553, vdata_2554, target_30)
and vn_2549.getType().hasName("int")
and vlength_2551.getType().hasName("unsigned short")
and vsize_2553.getType().hasName("unsigned short")
and vdata_2554.getType().hasName("unsigned char *")
and vd_2549.getType().hasName("unsigned char *")
and vn_2549.getParentScope+() = func
and vlength_2551.getParentScope+() = func
and vsize_2553.getParentScope+() = func
and vdata_2554.getParentScope+() = func
and vd_2549.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
