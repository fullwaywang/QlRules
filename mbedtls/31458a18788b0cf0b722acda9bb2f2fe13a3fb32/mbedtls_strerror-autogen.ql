/**
 * @name mbedtls-31458a18788b0cf0b722acda9bb2f2fe13a3fb32-mbedtls_strerror
 * @id cpp/mbedtls/31458a18788b0cf0b722acda9bb2f2fe13a3fb32/mbedtls-strerror
 * @description mbedtls-31458a18788b0cf0b722acda9bb2f2fe13a3fb32-library/error.c-mbedtls_strerror CVE-2017-14032
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuflen_153, Variable vuse_ret_156, Parameter vbuf_153, BitwiseAndExpr target_1, ExprStmt target_2, ExprStmt target_3, EqualityOperation target_4, EqualityOperation target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vuse_ret_156
		and target_0.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="12288"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_153
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuflen_153
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="X509 - A fatal error occured, eg the chain is too long or the vrfy callback failed"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(139)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(BitwiseAndExpr target_1) {
		target_1.getRightOperand().(HexLiteral).getValue()="65408"
}

predicate func_2(Parameter vbuflen_153, Parameter vbuf_153, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_153
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuflen_153
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="X509 - Destination buffer is too small"
}

predicate func_3(Parameter vbuflen_153, Variable vuse_ret_156, Parameter vbuf_153, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_153
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuflen_153
		and target_3.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="UNKNOWN ERROR CODE (%04X)"
		and target_3.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vuse_ret_156
}

predicate func_4(Variable vuse_ret_156, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vuse_ret_156
		and target_4.getAnOperand().(UnaryMinusExpr).getValue()="10624"
}

predicate func_5(Parameter vbuf_153, EqualityOperation target_5) {
		target_5.getAnOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_153
		and target_5.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vbuflen_153, Variable vuse_ret_156, Parameter vbuf_153, BitwiseAndExpr target_1, ExprStmt target_2, ExprStmt target_3, EqualityOperation target_4, EqualityOperation target_5
where
not func_0(vbuflen_153, vuse_ret_156, vbuf_153, target_1, target_2, target_3, target_4, target_5)
and func_1(target_1)
and func_2(vbuflen_153, vbuf_153, target_2)
and func_3(vbuflen_153, vuse_ret_156, vbuf_153, target_3)
and func_4(vuse_ret_156, target_4)
and func_5(vbuf_153, target_5)
and vbuflen_153.getType().hasName("size_t")
and vuse_ret_156.getType().hasName("int")
and vbuf_153.getType().hasName("char *")
and vbuflen_153.getParentScope+() = func
and vuse_ret_156.getParentScope+() = func
and vbuf_153.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
