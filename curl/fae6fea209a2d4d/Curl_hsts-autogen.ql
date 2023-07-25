/**
 * @name curl-fae6fea209a2d4d-Curl_hsts
 * @id cpp/curl/fae6fea209a2d4d/Curl-hsts
 * @description curl-fae6fea209a2d4d-Curl_hsts CVE-2022-30115
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vh_237) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof ArrayType
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vh_237)
}

predicate func_1(Parameter vh_237, Variable vhlen_242) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vhlen_242
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="256"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vhlen_242
		and target_1.getThen() instanceof ReturnStmt
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vh_237)
}

predicate func_2(Parameter vh_237, Parameter vhostname_237, Variable vhlen_242) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char[257]")
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhostname_237
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vhlen_242
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vh_237)
}

predicate func_3(Parameter vh_237, Parameter vhostname_237, Variable vhlen_242) {
	exists(IfStmt target_3 |
		target_3.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhostname_237
		and target_3.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vhlen_242
		and target_3.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="46"
		and target_3.getThen().(ExprStmt).getExpr().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vhlen_242
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vh_237)
}

predicate func_4(Parameter vh_237, Variable vhlen_242) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("char[257]")
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vhlen_242
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vh_237)
}

predicate func_5(Parameter vh_237, Parameter vhostname_237) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhostname_237
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("char[257]")
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vh_237)
}

predicate func_7(Function func) {
	exists(ReturnStmt target_7 |
		target_7.getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

predicate func_8(Parameter vhostname_237) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("strlen")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vhostname_237)
}

predicate func_9(Parameter vhostname_237, Variable voffs_257) {
	exists(ArrayExpr target_9 |
		target_9.getArrayBase().(VariableAccess).getTarget()=vhostname_237
		and target_9.getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=voffs_257
		and target_9.getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1")
}

from Function func, Parameter vh_237, Parameter vhostname_237, Variable vhlen_242, Variable voffs_257
where
not func_0(vh_237)
and not func_1(vh_237, vhlen_242)
and not func_2(vh_237, vhostname_237, vhlen_242)
and not func_3(vh_237, vhostname_237, vhlen_242)
and not func_4(vh_237, vhlen_242)
and not func_5(vh_237, vhostname_237)
and func_7(func)
and vh_237.getType().hasName("hsts *")
and vhostname_237.getType().hasName("const char *")
and func_8(vhostname_237)
and func_9(vhostname_237, voffs_257)
and vhlen_242.getType().hasName("size_t")
and voffs_257.getType().hasName("size_t")
and vh_237.getParentScope+() = func
and vhostname_237.getParentScope+() = func
and vhlen_242.getParentScope+() = func
and voffs_257.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
