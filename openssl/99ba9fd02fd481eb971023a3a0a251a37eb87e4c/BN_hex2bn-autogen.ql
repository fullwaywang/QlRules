/**
 * @name openssl-99ba9fd02fd481eb971023a3a0a251a37eb87e4c-BN_hex2bn
 * @id cpp/openssl/99ba9fd02fd481eb971023a3a0a251a37eb87e4c/BN-hex2bn
 * @description openssl-99ba9fd02fd481eb971023a3a0a251a37eb87e4c-crypto/bn/bn_print.c-BN_hex2bn CVE-2016-0797
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="8"
		and not target_0.getValue()="2147483647"
		and target_0.getParent().(MulExpr).getParent().(AddExpr).getAnOperand() instanceof MulExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="8"
		and not target_1.getValue()="2147483647"
		and target_1.getParent().(MulExpr).getParent().(AddExpr).getAnOperand() instanceof MulExpr
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, Literal target_2) {
		target_2.getValue()="1"
		and not target_2.getValue()="4"
		and target_2.getParent().(SubExpr).getParent().(DivExpr).getLeftOperand() instanceof SubExpr
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vret_173, FunctionCall target_3) {
		target_3.getTarget().hasName("bn_expand2")
		and not target_3.getTarget().hasName("bn_expand")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vret_173
		and target_3.getArgument(1).(DivExpr).getLeftOperand() instanceof SubExpr
		and target_3.getArgument(1).(DivExpr).getRightOperand() instanceof MulExpr
}

predicate func_4(Variable vi_175, EmptyStmt target_15, ExprStmt target_22) {
	exists(LogicalAndExpr target_4 |
		target_4.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_175
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(DivExpr).getValue()="536870911"
		and target_4.getAnOperand() instanceof BitwiseAndExpr
		and target_4.getParent().(ForStmt).getStmt()=target_15
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_5(Variable vret_173) {
	exists(DivExpr target_5 |
		target_5.getValue()="536870911"
		and target_5.getParent().(LEExpr).getLesserOperand() instanceof DivExpr
		and target_5.getParent().(LEExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="dmax"
		and target_5.getParent().(LEExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173)
}

*/
predicate func_6(Function func) {
	exists(ContinueStmt target_6 |
		target_6.toString() = "continue;"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Variable vi_175, GotoStmt target_23, ExprStmt target_24) {
	exists(RelationalOperation target_7 |
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vi_175
		and target_7.getLesserOperand().(DivExpr).getValue()="536870911"
		and target_7.getParent().(IfStmt).getThen()=target_23
		and target_24.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_8(Variable vret_173, ExprStmt target_27, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("bn_expand")
		and target_8.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vret_173
		and target_8.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1) instanceof MulExpr
		and target_8.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getThen().(GotoStmt).toString() = "goto ..."
		and target_8.getThen().(GotoStmt).getName() ="err"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_8)
		and target_8.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_27.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_10(Parameter va_171, Variable vi_175, EmptyStmt target_15, BitwiseAndExpr target_10) {
		target_10.getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_b_loc")
		and target_10.getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=va_171
		and target_10.getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_175
		and target_10.getParent().(ForStmt).getStmt()=target_15
}

predicate func_11(Variable vi_175, MulExpr target_11) {
		target_11.getLeftOperand().(VariableAccess).getTarget()=vi_175
		and target_11.getRightOperand().(Literal).getValue()="4"
}

predicate func_13(Variable vi_175, VariableAccess target_13) {
		target_13.getTarget()=vi_175
}

predicate func_14(Function func, LabelStmt target_14) {
		target_14.toString() = "label ...:"
		and target_14.getName() ="err"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

predicate func_15(Function func, EmptyStmt target_15) {
		target_15.toString() = ";"
		and target_15.getEnclosingFunction() = func
}

predicate func_16(Variable vret_173, GotoStmt target_23, ConditionalExpr target_16) {
		target_16.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand() instanceof MulExpr
		and target_16.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getValue()="64"
		and target_16.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(SubExpr).getRightOperand() instanceof Literal
		and target_16.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(MulExpr).getValue()="64"
		and target_16.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="dmax"
		and target_16.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_16.getThen().(VariableAccess).getTarget()=vret_173
		and target_16.getElse() instanceof FunctionCall
		and target_16.getParent().(EQExpr).getAnOperand().(Literal).getValue()="0"
		and target_16.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_23
}

/*predicate func_17(Variable vret_173, ExprStmt target_28, DivExpr target_17) {
		target_17.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand() instanceof MulExpr
		and target_17.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getValue()="64"
		and target_17.getLeftOperand().(SubExpr).getRightOperand() instanceof Literal
		and target_17.getRightOperand().(MulExpr).getValue()="64"
		and target_17.getParent().(LEExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="dmax"
		and target_17.getParent().(LEExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_28.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_17.getParent().(LEExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
/*predicate func_18(Variable vret_173, PointerFieldAccess target_18) {
		target_18.getTarget().getName()="dmax"
		and target_18.getQualifier().(VariableAccess).getTarget()=vret_173
}

*/
predicate func_19(Variable vi_175, ExprStmt target_22, SubExpr target_19) {
		target_19.getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vi_175
		and target_19.getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand() instanceof Literal
		and target_19.getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getValue()="64"
		and target_19.getRightOperand().(Literal).getValue()="1"
		and target_19.getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_20(Function func, MulExpr target_20) {
		target_20.getValue()="64"
		and target_20.getEnclosingFunction() = func
}

predicate func_22(Variable vi_175, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vi_175
}

predicate func_23(GotoStmt target_23) {
		target_23.toString() = "goto ..."
		and target_23.getName() ="err"
}

predicate func_24(Variable vi_175, ExprStmt target_24) {
		target_24.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_175
}

predicate func_27(Variable vret_173, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="d"
		and target_27.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
}

predicate func_28(Variable vret_173, ExprStmt target_28) {
		target_28.getExpr().(FunctionCall).getTarget().hasName("BN_set_word")
		and target_28.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vret_173
		and target_28.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

from Function func, Parameter va_171, Variable vret_173, Variable vi_175, Literal target_0, Literal target_1, Literal target_2, FunctionCall target_3, BitwiseAndExpr target_10, MulExpr target_11, VariableAccess target_13, LabelStmt target_14, EmptyStmt target_15, ConditionalExpr target_16, SubExpr target_19, MulExpr target_20, ExprStmt target_22, GotoStmt target_23, ExprStmt target_24, ExprStmt target_27, ExprStmt target_28
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(vret_173, target_3)
and not func_4(vi_175, target_15, target_22)
and not func_6(func)
and not func_7(vi_175, target_23, target_24)
and not func_8(vret_173, target_27, func)
and func_10(va_171, vi_175, target_15, target_10)
and func_11(vi_175, target_11)
and func_13(vi_175, target_13)
and func_14(func, target_14)
and func_15(func, target_15)
and func_16(vret_173, target_23, target_16)
and func_19(vi_175, target_22, target_19)
and func_20(func, target_20)
and func_22(vi_175, target_22)
and func_23(target_23)
and func_24(vi_175, target_24)
and func_27(vret_173, target_27)
and func_28(vret_173, target_28)
and va_171.getType().hasName("const char *")
and vret_173.getType().hasName("BIGNUM *")
and vi_175.getType().hasName("int")
and va_171.getParentScope+() = func
and vret_173.getParentScope+() = func
and vi_175.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
