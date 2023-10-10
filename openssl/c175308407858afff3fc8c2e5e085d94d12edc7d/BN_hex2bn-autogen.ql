/**
 * @name openssl-c175308407858afff3fc8c2e5e085d94d12edc7d-BN_hex2bn
 * @id cpp/openssl/c175308407858afff3fc8c2e5e085d94d12edc7d/BN-hex2bn
 * @description openssl-c175308407858afff3fc8c2e5e085d94d12edc7d-BN_hex2bn CVE-2016-0797
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_181) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_181
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(DivExpr).getValue()="536870911"
		and target_0.getAnOperand() instanceof BitwiseAndExpr
		and target_0.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(0).(ContinueStmt).toString() = "continue;"
		and target_0.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(1).(LabelStmt).toString() = "label ...:")
}

predicate func_3(Variable vi_181) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vi_181
		and target_3.getLesserOperand().(DivExpr).getValue()="536870911"
		and target_3.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_4(Variable vi_181, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(EqualityOperation).getAnOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vi_181
		and target_4.getCondition().(EqualityOperation).getAnOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(Literal).getValue()="4"
		and target_4.getCondition().(EqualityOperation).getAnOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getValue()="2147483584"
		and target_4.getCondition().(EqualityOperation).getAnOperand().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_4.getCondition().(EqualityOperation).getAnOperand().(ConditionalExpr).getElse() instanceof ConditionalExpr
		and target_4.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getThen().(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_4))
}

predicate func_6(Parameter va_177, Variable vi_181) {
	exists(BitwiseAndExpr target_6 |
		target_6.getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_b_loc")
		and target_6.getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=va_177
		and target_6.getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_181
		and target_6.getParent().(ForStmt).getStmt() instanceof EmptyStmt)
}

predicate func_7(Variable vret_179, Variable vi_181) {
	exists(ConditionalExpr target_7 |
		target_7.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vi_181
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="4"
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="64"
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(Literal).getValue()="64"
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="dmax"
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_179
		and target_7.getThen().(VariableAccess).getTarget()=vret_179
		and target_7.getElse().(FunctionCall).getTarget().hasName("bn_expand2")
		and target_7.getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vret_179
		and target_7.getElse().(FunctionCall).getArgument(1).(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vi_181
		and target_7.getElse().(FunctionCall).getArgument(1).(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="4"
		and target_7.getElse().(FunctionCall).getArgument(1).(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="64"
		and target_7.getElse().(FunctionCall).getArgument(1).(DivExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_7.getElse().(FunctionCall).getArgument(1).(DivExpr).getRightOperand().(Literal).getValue()="64"
		and target_7.getParent().(EQExpr).getAnOperand().(Literal).getValue()="0"
		and target_7.getParent().(EQExpr).getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_8(Function func) {
	exists(EmptyStmt target_8 |
		target_8.toString() = ";"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Variable vi_181) {
	exists(AssignExpr target_9 |
		target_9.getLValue().(VariableAccess).getTarget()=vi_181
		and target_9.getRValue().(Literal).getValue()="0")
}

predicate func_10(Variable vneg_181, Variable vi_181, Variable vnum_182) {
	exists(AssignExpr target_10 |
		target_10.getLValue().(VariableAccess).getTarget()=vnum_182
		and target_10.getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_181
		and target_10.getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vneg_181)
}

from Function func, Parameter va_177, Variable vret_179, Variable vneg_181, Variable vi_181, Variable vnum_182
where
not func_0(vi_181)
and not func_3(vi_181)
and not func_4(vi_181, func)
and func_6(va_177, vi_181)
and func_7(vret_179, vi_181)
and func_8(func)
and va_177.getType().hasName("const char *")
and vret_179.getType().hasName("BIGNUM *")
and vi_181.getType().hasName("int")
and func_9(vi_181)
and func_10(vneg_181, vi_181, vnum_182)
and vnum_182.getType().hasName("int")
and va_177.getParentScope+() = func
and vret_179.getParentScope+() = func
and vneg_181.getParentScope+() = func
and vi_181.getParentScope+() = func
and vnum_182.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
