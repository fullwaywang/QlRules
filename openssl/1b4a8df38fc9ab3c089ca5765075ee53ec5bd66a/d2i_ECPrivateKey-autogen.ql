/**
 * @name openssl-1b4a8df38fc9ab3c089ca5765075ee53ec5bd66a-d2i_ECPrivateKey
 * @id cpp/openssl/1b4a8df38fc9ab3c089ca5765075ee53ec5bd66a/d2i-ECPrivateKey
 * @description openssl-1b4a8df38fc9ab3c089ca5765075ee53ec5bd66a-d2i_ECPrivateKey CVE-2015-0209
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter va_995, Variable vret_998) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vret_998
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=va_995
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=va_995
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_998
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("EC_KEY_free")
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vret_998)
}

predicate func_1(Parameter va_995, Variable vret_998) {
	exists(IfStmt target_1 |
		target_1.getCondition().(VariableAccess).getTarget()=va_995
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=va_995
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vret_998
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=va_995
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=va_995
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_3(Parameter va_995, Variable vret_998) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vret_998
		and target_3.getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=va_995)
}

predicate func_4(Variable vret_998, Variable vpub_oct_1049, Variable vpub_oct_len_1050) {
	exists(NotExpr target_4 |
		target_4.getOperand().(FunctionCall).getTarget().hasName("EC_POINT_oct2point")
		and target_4.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="group"
		and target_4.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_998
		and target_4.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pub_key"
		and target_4.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_998
		and target_4.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpub_oct_1049
		and target_4.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vpub_oct_len_1050
		and target_4.getOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

from Function func, Parameter va_995, Variable vret_998, Variable vpub_oct_1049, Variable vpub_oct_len_1050
where
not func_0(va_995, vret_998)
and func_1(va_995, vret_998)
and va_995.getType().hasName("EC_KEY **")
and func_3(va_995, vret_998)
and vret_998.getType().hasName("EC_KEY *")
and func_4(vret_998, vpub_oct_1049, vpub_oct_len_1050)
and vpub_oct_1049.getType().hasName("const unsigned char *")
and vpub_oct_len_1050.getType().hasName("size_t")
and va_995.getParentScope+() = func
and vret_998.getParentScope+() = func
and vpub_oct_1049.getParentScope+() = func
and vpub_oct_len_1050.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
