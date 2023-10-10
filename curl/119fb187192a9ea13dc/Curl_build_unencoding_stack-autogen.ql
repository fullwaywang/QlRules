/**
 * @name curl-119fb187192a9ea13dc-Curl_build_unencoding_stack
 * @id cpp/curl/119fb187192a9ea13dc/Curl-build-unencoding-stack
 * @description curl-119fb187192a9ea13dc-lib/content_encoding.c-Curl_build_unencoding_stack CVE-2023-23916
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="5"
		and target_0.getParent() instanceof Initializer
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="Reject response due to %u content encodings"
		and not target_1.getValue()="Reject response due to more than %u content encodings"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vk_1049, BlockStmt target_6, NotExpr target_7, RelationalOperation target_8) {
	exists(PostfixIncrExpr target_2 |
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="writer_stack_depth"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vk_1049
		and target_2.getParent().(GEExpr).getGreaterOperand() instanceof PrefixIncrExpr
		and target_2.getParent().(GEExpr).getLesserOperand().(Literal).getValue()="5"
		and target_2.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_6
		and target_7.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Function func, DeclStmt target_3) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Variable vcounter_1050, BlockStmt target_6, PrefixIncrExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vcounter_1050
		and target_4.getParent().(GEExpr).getLesserOperand().(Literal).getValue()="5"
		and target_4.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_6
}

predicate func_5(Variable vcounter_1050, VariableAccess target_5) {
		target_5.getTarget()=vcounter_1050
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_failf")
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Curl_easy *")
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
}

predicate func_6(Variable vcounter_1050, BlockStmt target_6) {
		target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_failf")
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Curl_easy *")
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcounter_1050
}

predicate func_7(Variable vk_1049, NotExpr target_7) {
		target_7.getOperand().(PointerFieldAccess).getTarget().getName()="writer_stack"
		and target_7.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vk_1049
}

predicate func_8(Variable vk_1049, RelationalOperation target_8) {
		 (target_8 instanceof GEExpr or target_8 instanceof LEExpr)
		and target_8.getGreaterOperand().(VariableAccess).getTarget().getType().hasName("unsigned int")
		and target_8.getLesserOperand().(PointerFieldAccess).getTarget().getName()="order"
		and target_8.getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="writer_stack"
		and target_8.getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vk_1049
}

from Function func, Variable vk_1049, Variable vcounter_1050, Literal target_0, StringLiteral target_1, DeclStmt target_3, PrefixIncrExpr target_4, VariableAccess target_5, BlockStmt target_6, NotExpr target_7, RelationalOperation target_8
where
func_0(func, target_0)
and func_1(func, target_1)
and not func_2(vk_1049, target_6, target_7, target_8)
and func_3(func, target_3)
and func_4(vcounter_1050, target_6, target_4)
and func_5(vcounter_1050, target_5)
and func_6(vcounter_1050, target_6)
and func_7(vk_1049, target_7)
and func_8(vk_1049, target_8)
and vk_1049.getType().hasName("SingleRequest *")
and vcounter_1050.getType().hasName("int")
and vk_1049.(LocalVariable).getFunction() = func
and vcounter_1050.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
