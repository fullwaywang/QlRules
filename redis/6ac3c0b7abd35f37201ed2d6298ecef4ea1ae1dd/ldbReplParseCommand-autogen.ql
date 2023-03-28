/**
 * @name redis-6ac3c0b7abd35f37201ed2d6298ecef4ea1ae1dd-ldbReplParseCommand
 * @id cpp/redis/6ac3c0b7abd35f37201ed2d6298ecef4ea1ae1dd/ldbReplParseCommand
 * @description redis-6ac3c0b7abd35f37201ed2d6298ecef4ea1ae1dd-ldbReplParseCommand CVE-2021-32672
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_2037, ExprStmt target_4, EqualityOperation target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_2037
		and target_0.getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and target_4.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcopy_2036, Variable vp_2037, Variable vslen_2059, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, LogicalOrExpr target_9) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_2037
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vslen_2059
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vcopy_2036
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("sdslen")
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcopy_2036
		and target_1.getThen().(GotoStmt).toString() = "goto ..."
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_7.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_9.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("char **")
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("char *")
		and (func.getEntryPoint().(BlockStmt).getStmt(21)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(21).getFollowingStmt()=target_2))
}

predicate func_4(Variable vp_2037, ExprStmt target_4) {
		target_4.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_2037
		and target_4.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_5(Variable vp_2037, EqualityOperation target_5) {
		target_5.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_2037
		and target_5.getAnOperand().(CharLiteral).getValue()="36"
}

predicate func_6(Variable vcopy_2036, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("sdsfree")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcopy_2036
}

predicate func_7(Variable vp_2037, ExprStmt target_7) {
		target_7.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_2037
		and target_7.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_8(Variable vp_2037, Variable vslen_2059, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("sds *")
		and target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sdsnewlen")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_2037
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vslen_2059
}

predicate func_9(Variable vslen_2059, LogicalOrExpr target_9) {
		target_9.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vslen_2059
		and target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vslen_2059
		and target_9.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1024"
}

from Function func, Variable vcopy_2036, Variable vp_2037, Variable vslen_2059, ExprStmt target_4, EqualityOperation target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, LogicalOrExpr target_9
where
not func_0(vp_2037, target_4, target_5)
and not func_1(vcopy_2036, vp_2037, vslen_2059, target_6, target_7, target_8, target_9)
and not func_2(func)
and func_4(vp_2037, target_4)
and func_5(vp_2037, target_5)
and func_6(vcopy_2036, target_6)
and func_7(vp_2037, target_7)
and func_8(vp_2037, vslen_2059, target_8)
and func_9(vslen_2059, target_9)
and vcopy_2036.getType().hasName("sds")
and vp_2037.getType().hasName("char *")
and vslen_2059.getType().hasName("int")
and vcopy_2036.getParentScope+() = func
and vp_2037.getParentScope+() = func
and vslen_2059.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
