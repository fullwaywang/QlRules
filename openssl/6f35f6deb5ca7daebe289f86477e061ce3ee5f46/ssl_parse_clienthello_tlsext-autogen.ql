/**
 * @name openssl-6f35f6deb5ca7daebe289f86477e061ce3ee5f46-ssl_parse_clienthello_tlsext
 * @id cpp/openssl/6f35f6deb5ca7daebe289f86477e061ce3ee5f46/ssl-parse-clienthello-tlsext
 * @description openssl-6f35f6deb5ca7daebe289f86477e061ce3ee5f46-ssl/t1_lib.c-ssl_parse_clienthello_tlsext CVE-2016-2177
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlimit_985, Variable vdata_990, GotoStmt target_20, EqualityOperation target_21, EqualityOperation target_22, ExprStmt target_23) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vlimit_985
		and target_0.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vdata_990
		and target_0.getGreaterOperand() instanceof Literal
		and target_0.getParent().(IfStmt).getThen()=target_20
		and target_21.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_22.getAnOperand().(VariableAccess).getLocation())
		and target_0.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_23.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vlimit_985, Variable vdata_990, GotoStmt target_24, EqualityOperation target_22, RelationalOperation target_19, ExprStmt target_23, RelationalOperation target_18) {
	exists(PointerArithmeticOperation target_1 |
		target_1.getLeftOperand().(VariableAccess).getTarget()=vlimit_985
		and target_1.getRightOperand().(VariableAccess).getTarget()=vdata_990
		and target_1.getParent().(NEExpr).getAnOperand() instanceof PointerArithmeticOperation
		and target_1.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vlimit_985
		and target_1.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_24
		and target_22.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getLeftOperand().(VariableAccess).getLocation())
		and target_1.getLeftOperand().(VariableAccess).getLocation().isBefore(target_19.getLesserOperand().(VariableAccess).getLocation())
		and target_23.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_1.getRightOperand().(VariableAccess).getLocation())
		and target_1.getRightOperand().(VariableAccess).getLocation().isBefore(target_18.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vlimit_985, Variable vdata_990, RelationalOperation target_16, RelationalOperation target_18, EqualityOperation target_22, ExprStmt target_25) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vlimit_985
		and target_2.getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vdata_990
		and target_2.getLesserOperand() instanceof Literal
		and target_16.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_2.getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_18.getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_2.getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_25.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vlimit_985, Variable vsize_988, Variable vdata_990, GotoStmt target_26, RelationalOperation target_18, EqualityOperation target_27, ExprStmt target_28, ExprStmt target_29) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vlimit_985
		and target_3.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vdata_990
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vsize_988
		and target_3.getParent().(IfStmt).getThen()=target_26
		and target_18.getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_3.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_3.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_27.getAnOperand().(VariableAccess).getLocation())
		and target_28.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getGreaterOperand().(VariableAccess).getLocation())
		and target_3.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_29.getExpr().(VariableCall).getArgument(4).(VariableAccess).getLocation()))
}

predicate func_4(Parameter vlimit_985, VariableAccess target_4) {
		target_4.getTarget()=vlimit_985
}

predicate func_5(Variable vlen_989, VariableAccess target_5) {
		target_5.getTarget()=vlen_989
}

predicate func_6(Parameter vlimit_985, VariableAccess target_6) {
		target_6.getTarget()=vlimit_985
}

predicate func_7(Variable vdata_990, GotoStmt target_20, VariableAccess target_7) {
		target_7.getTarget()=vdata_990
		and target_7.getParent().(GTExpr).getLesserOperand() instanceof PointerArithmeticOperation
		and target_7.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_20
}

predicate func_9(Variable vdata_990, VariableAccess target_9) {
		target_9.getTarget()=vdata_990
}

predicate func_10(Parameter vlimit_985, GotoStmt target_24, VariableAccess target_10) {
		target_10.getTarget()=vlimit_985
		and target_10.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_24
}

predicate func_11(Variable vdata_990, VariableAccess target_11) {
		target_11.getTarget()=vdata_990
		and target_11.getParent().(LEExpr).getGreaterOperand() instanceof PointerArithmeticOperation
}

predicate func_13(Variable vdata_990, VariableAccess target_13) {
		target_13.getTarget()=vdata_990
}

predicate func_14(Variable vsize_988, VariableAccess target_14) {
		target_14.getTarget()=vsize_988
}

predicate func_15(Parameter vlimit_985, GotoStmt target_26, VariableAccess target_15) {
		target_15.getTarget()=vlimit_985
		and target_15.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_15.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_26
}

predicate func_16(Parameter vlimit_985, Variable vdata_990, GotoStmt target_20, RelationalOperation target_16) {
		 (target_16 instanceof GTExpr or target_16 instanceof LTExpr)
		and target_16.getGreaterOperand().(VariableAccess).getTarget()=vdata_990
		and target_16.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vlimit_985
		and target_16.getLesserOperand().(PointerArithmeticOperation).getRightOperand() instanceof Literal
		and target_16.getParent().(IfStmt).getThen()=target_20
}

predicate func_17(Parameter vlimit_985, Variable vlen_989, Variable vdata_990, GotoStmt target_24, PointerArithmeticOperation target_17) {
		target_17.getAnOperand().(VariableAccess).getTarget()=vdata_990
		and target_17.getAnOperand().(VariableAccess).getTarget()=vlen_989
		and target_17.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vlimit_985
		and target_17.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_24
}

predicate func_18(Parameter vlimit_985, Variable vdata_990, RelationalOperation target_18) {
		 (target_18 instanceof GEExpr or target_18 instanceof LEExpr)
		and target_18.getLesserOperand().(VariableAccess).getTarget()=vdata_990
		and target_18.getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vlimit_985
		and target_18.getGreaterOperand().(PointerArithmeticOperation).getRightOperand() instanceof Literal
}

predicate func_19(Parameter vlimit_985, Variable vsize_988, Variable vdata_990, GotoStmt target_26, RelationalOperation target_19) {
		 (target_19 instanceof GTExpr or target_19 instanceof LTExpr)
		and target_19.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_990
		and target_19.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsize_988
		and target_19.getLesserOperand().(VariableAccess).getTarget()=vlimit_985
		and target_19.getParent().(IfStmt).getThen()=target_26
}

predicate func_20(GotoStmt target_20) {
		target_20.toString() = "goto ..."
		and target_20.getName() ="err"
}

predicate func_21(Parameter vlimit_985, Variable vdata_990, EqualityOperation target_21) {
		target_21.getAnOperand().(VariableAccess).getTarget()=vdata_990
		and target_21.getAnOperand().(VariableAccess).getTarget()=vlimit_985
}

predicate func_22(Parameter vlimit_985, EqualityOperation target_22) {
		target_22.getAnOperand() instanceof PointerArithmeticOperation
		and target_22.getAnOperand().(VariableAccess).getTarget()=vlimit_985
}

predicate func_23(Variable vlen_989, Variable vdata_990, ExprStmt target_23) {
		target_23.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_989
		and target_23.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_990
		and target_23.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_23.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_23.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_990
		and target_23.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_23.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata_990
		and target_23.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_24(GotoStmt target_24) {
		target_24.toString() = "goto ..."
		and target_24.getName() ="err"
}

predicate func_25(Variable vdata_990, ExprStmt target_25) {
		target_25.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_990
		and target_25.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_25.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_25.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_990
		and target_25.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_25.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata_990
		and target_25.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_26(GotoStmt target_26) {
		target_26.toString() = "goto ..."
		and target_26.getName() ="err"
}

predicate func_27(Parameter vlimit_985, Variable vdata_990, EqualityOperation target_27) {
		target_27.getAnOperand().(VariableAccess).getTarget()=vdata_990
		and target_27.getAnOperand().(VariableAccess).getTarget()=vlimit_985
}

predicate func_28(Variable vsize_988, Variable vdata_990, ExprStmt target_28) {
		target_28.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_988
		and target_28.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_990
		and target_28.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_28.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_28.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_990
		and target_28.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_28.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata_990
		and target_28.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_29(Variable vsize_988, Variable vdata_990, ExprStmt target_29) {
		target_29.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="tlsext_debug_cb"
		and target_29.getExpr().(VariableCall).getArgument(1).(Literal).getValue()="0"
		and target_29.getExpr().(VariableCall).getArgument(3).(VariableAccess).getTarget()=vdata_990
		and target_29.getExpr().(VariableCall).getArgument(4).(VariableAccess).getTarget()=vsize_988
		and target_29.getExpr().(VariableCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="tlsext_debug_arg"
}

from Function func, Parameter vlimit_985, Variable vsize_988, Variable vlen_989, Variable vdata_990, VariableAccess target_4, VariableAccess target_5, VariableAccess target_6, VariableAccess target_7, VariableAccess target_9, VariableAccess target_10, VariableAccess target_11, VariableAccess target_13, VariableAccess target_14, VariableAccess target_15, RelationalOperation target_16, PointerArithmeticOperation target_17, RelationalOperation target_18, RelationalOperation target_19, GotoStmt target_20, EqualityOperation target_21, EqualityOperation target_22, ExprStmt target_23, GotoStmt target_24, ExprStmt target_25, GotoStmt target_26, EqualityOperation target_27, ExprStmt target_28, ExprStmt target_29
where
not func_0(vlimit_985, vdata_990, target_20, target_21, target_22, target_23)
and not func_1(vlimit_985, vdata_990, target_24, target_22, target_19, target_23, target_18)
and not func_2(vlimit_985, vdata_990, target_16, target_18, target_22, target_25)
and not func_3(vlimit_985, vsize_988, vdata_990, target_26, target_18, target_27, target_28, target_29)
and func_4(vlimit_985, target_4)
and func_5(vlen_989, target_5)
and func_6(vlimit_985, target_6)
and func_7(vdata_990, target_20, target_7)
and func_9(vdata_990, target_9)
and func_10(vlimit_985, target_24, target_10)
and func_11(vdata_990, target_11)
and func_13(vdata_990, target_13)
and func_14(vsize_988, target_14)
and func_15(vlimit_985, target_26, target_15)
and func_16(vlimit_985, vdata_990, target_20, target_16)
and func_17(vlimit_985, vlen_989, vdata_990, target_24, target_17)
and func_18(vlimit_985, vdata_990, target_18)
and func_19(vlimit_985, vsize_988, vdata_990, target_26, target_19)
and func_20(target_20)
and func_21(vlimit_985, vdata_990, target_21)
and func_22(vlimit_985, target_22)
and func_23(vlen_989, vdata_990, target_23)
and func_24(target_24)
and func_25(vdata_990, target_25)
and func_26(target_26)
and func_27(vlimit_985, vdata_990, target_27)
and func_28(vsize_988, vdata_990, target_28)
and func_29(vsize_988, vdata_990, target_29)
and vlimit_985.getType().hasName("unsigned char *")
and vsize_988.getType().hasName("unsigned short")
and vlen_989.getType().hasName("unsigned short")
and vdata_990.getType().hasName("unsigned char *")
and vlimit_985.getParentScope+() = func
and vsize_988.getParentScope+() = func
and vlen_989.getParentScope+() = func
and vdata_990.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
