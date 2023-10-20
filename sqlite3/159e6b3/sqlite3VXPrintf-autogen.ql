/**
 * @name sqlite3-159e6b304ccb5802dcf217678cba1948260d47cf-sqlite3VXPrintf
 * @id cpp/sqlite3/159e6b304ccb5802dcf217678cba1948260d47cf/sqlite3VXPrintf
 * @description sqlite3-159e6b304ccb5802dcf217678cba1948260d47cf-src/printf.c-sqlite3VXPrintf CVE-2015-3416
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vwidth_185, ExprStmt target_24, LogicalAndExpr target_25) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vwidth_185
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(UnaryMinusExpr).getValue()="-2147483647"
		and target_0.getThen() instanceof UnaryMinusExpr
		and target_0.getElse().(Literal).getValue()="0"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwidth_185
		and target_24.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_25.getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vc_180, LogicalAndExpr target_26) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getType().hasName("unsigned int")
		and target_1.getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_1.getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand() instanceof Literal
		and target_1.getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vc_180
		and target_1.getRValue().(SubExpr).getRightOperand() instanceof CharLiteral
		and target_26.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(EqualityOperation target_27, Function func) {
	exists(EmptyStmt target_2 |
		target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_27
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vwidth_185) {
	exists(BitwiseAndExpr target_3 |
		target_3.getLeftOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_3.getRightOperand().(HexLiteral).getValue()="2147483647"
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwidth_185)
}

predicate func_4(Variable vprecision_182, ExprStmt target_28, LogicalOrExpr target_29) {
	exists(ConditionalExpr target_4 |
		target_4.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vprecision_182
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(UnaryMinusExpr).getValue()="-2147483647"
		and target_4.getThen() instanceof UnaryMinusExpr
		and target_4.getElse().(UnaryMinusExpr).getValue()="-1"
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vprecision_182
		and target_28.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_4.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_29.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_5(Variable vc_180, LogicalAndExpr target_30) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("unsigned int")
		and target_5.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_5.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand() instanceof Literal
		and target_5.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vc_180
		and target_5.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand() instanceof CharLiteral
		and target_30.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_6(EqualityOperation target_31, Function func) {
	exists(EmptyStmt target_6 |
		target_6.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_31
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Variable vprecision_182, EqualityOperation target_31, ExprStmt target_32) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vprecision_182
		and target_7.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_7.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="2147483647"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(3)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_31
		and target_32.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

/*predicate func_8(Variable vprecision_182) {
	exists(BitwiseAndExpr target_8 |
		target_8.getLeftOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_8.getRightOperand().(HexLiteral).getValue()="2147483647"
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vprecision_182)
}

*/
predicate func_9(VariableAccess target_33, Function func) {
	exists(EmptyStmt target_9 |
		target_9.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_33
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Variable vprecision_182, ExprStmt target_34) {
	exists(BitwiseAndExpr target_10 |
		target_10.getLeftOperand().(VariableAccess).getTarget()=vprecision_182
		and target_10.getRightOperand().(HexLiteral).getValue()="4095"
		and target_10.getParent().(AssignExpr).getRValue() = target_10
		and target_10.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_34.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_10.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_11(Variable vwidth_185, UnaryMinusExpr target_11) {
		target_11.getOperand().(VariableAccess).getTarget()=vwidth_185
		and target_11.getParent().(AssignExpr).getRValue() = target_11
		and target_11.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwidth_185
}

predicate func_12(Variable vprecision_182, UnaryMinusExpr target_12) {
		target_12.getOperand().(VariableAccess).getTarget()=vprecision_182
		and target_12.getParent().(AssignExpr).getRValue() = target_12
		and target_12.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vprecision_182
}

predicate func_14(Variable vc_180, VariableAccess target_14) {
		target_14.getTarget()=vc_180
}

predicate func_16(Variable vprecision_182, VariableAccess target_16) {
		target_16.getTarget()=vprecision_182
}

predicate func_18(Variable vc_180, VariableAccess target_18) {
		target_18.getTarget()=vc_180
}

predicate func_20(Variable vwidth_185, VariableAccess target_20) {
		target_20.getTarget()=vwidth_185
}

predicate func_21(Variable vprecision_182, VariableAccess target_21) {
		target_21.getTarget()=vprecision_182
		and target_21.getParent().(AssignExpr).getRValue() = target_21
		and target_21.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_22(Variable vc_180, Variable vwidth_185, SubExpr target_22) {
		target_22.getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vwidth_185
		and target_22.getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand() instanceof Literal
		and target_22.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vc_180
		and target_22.getRightOperand() instanceof CharLiteral
		and target_22.getParent().(AssignExpr).getRValue() = target_22
		and target_22.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwidth_185
}

predicate func_23(Variable vc_180, Variable vprecision_182, SubExpr target_23) {
		target_23.getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vprecision_182
		and target_23.getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand() instanceof Literal
		and target_23.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vc_180
		and target_23.getRightOperand() instanceof CharLiteral
		and target_23.getParent().(AssignExpr).getRValue() = target_23
		and target_23.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vprecision_182
}

predicate func_24(Variable vwidth_185, ExprStmt target_24) {
		target_24.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwidth_185
		and target_24.getExpr().(AssignExpr).getRValue() instanceof SubExpr
}

predicate func_25(Variable vprecision_182, Variable vwidth_185, LogicalAndExpr target_25) {
		target_25.getAnOperand().(VariableAccess).getTarget().getType().hasName("etByte")
		and target_25.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vprecision_182
		and target_25.getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vwidth_185
		and target_25.getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("char")
		and target_25.getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_26(Variable vc_180, LogicalAndExpr target_26) {
		target_26.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vc_180
		and target_26.getAnOperand().(RelationalOperation).getLesserOperand().(CharLiteral).getValue()="48"
		and target_26.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vc_180
		and target_26.getAnOperand().(RelationalOperation).getGreaterOperand().(CharLiteral).getValue()="57"
}

predicate func_27(Variable vc_180, EqualityOperation target_27) {
		target_27.getAnOperand().(VariableAccess).getTarget()=vc_180
		and target_27.getAnOperand().(CharLiteral).getValue()="42"
}

predicate func_28(Variable vprecision_182, ExprStmt target_28) {
		target_28.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vprecision_182
}

predicate func_29(Variable vprecision_182, LogicalOrExpr target_29) {
		target_29.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_29.getAnOperand().(RelationalOperation).getGreaterOperand().(UnaryMinusExpr).getValue()="-4"
		and target_29.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_29.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vprecision_182
}

predicate func_30(Variable vc_180, LogicalAndExpr target_30) {
		target_30.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vc_180
		and target_30.getAnOperand().(RelationalOperation).getLesserOperand().(CharLiteral).getValue()="48"
		and target_30.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vc_180
		and target_30.getAnOperand().(RelationalOperation).getGreaterOperand().(CharLiteral).getValue()="57"
}

predicate func_31(Variable vc_180, EqualityOperation target_31) {
		target_31.getAnOperand().(VariableAccess).getTarget()=vc_180
		and target_31.getAnOperand().(CharLiteral).getValue()="42"
}

predicate func_32(Variable vprecision_182, ExprStmt target_32) {
		target_32.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vprecision_182
		and target_32.getExpr().(AssignExpr).getRValue() instanceof UnaryMinusExpr
}

predicate func_33(Variable vxtype_195, VariableAccess target_33) {
		target_33.getTarget()=vxtype_195
}

predicate func_34(Variable vprecision_182, ExprStmt target_34) {
		target_34.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vprecision_182
		and target_34.getExpr().(AssignExpr).getRValue() instanceof SubExpr
}

from Function func, Variable vc_180, Variable vprecision_182, Variable vwidth_185, Variable vxtype_195, UnaryMinusExpr target_11, UnaryMinusExpr target_12, VariableAccess target_14, VariableAccess target_16, VariableAccess target_18, VariableAccess target_20, VariableAccess target_21, SubExpr target_22, SubExpr target_23, ExprStmt target_24, LogicalAndExpr target_25, LogicalAndExpr target_26, EqualityOperation target_27, ExprStmt target_28, LogicalOrExpr target_29, LogicalAndExpr target_30, EqualityOperation target_31, ExprStmt target_32, VariableAccess target_33, ExprStmt target_34
where
not func_0(vwidth_185, target_24, target_25)
and not func_1(vc_180, target_26)
and not func_2(target_27, func)
and not func_3(vwidth_185)
and not func_4(vprecision_182, target_28, target_29)
and not func_5(vc_180, target_30)
and not func_6(target_31, func)
and not func_7(vprecision_182, target_31, target_32)
and not func_9(target_33, func)
and not func_10(vprecision_182, target_34)
and func_11(vwidth_185, target_11)
and func_12(vprecision_182, target_12)
and func_14(vc_180, target_14)
and func_16(vprecision_182, target_16)
and func_18(vc_180, target_18)
and func_20(vwidth_185, target_20)
and func_21(vprecision_182, target_21)
and func_22(vc_180, vwidth_185, target_22)
and func_23(vc_180, vprecision_182, target_23)
and func_24(vwidth_185, target_24)
and func_25(vprecision_182, vwidth_185, target_25)
and func_26(vc_180, target_26)
and func_27(vc_180, target_27)
and func_28(vprecision_182, target_28)
and func_29(vprecision_182, target_29)
and func_30(vc_180, target_30)
and func_31(vc_180, target_31)
and func_32(vprecision_182, target_32)
and func_33(vxtype_195, target_33)
and func_34(vprecision_182, target_34)
and vc_180.getType().hasName("int")
and vprecision_182.getType().hasName("int")
and vwidth_185.getType().hasName("int")
and vxtype_195.getType().hasName("etByte")
and vc_180.(LocalVariable).getFunction() = func
and vprecision_182.(LocalVariable).getFunction() = func
and vwidth_185.(LocalVariable).getFunction() = func
and vxtype_195.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
