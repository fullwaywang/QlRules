/**
 * @name openssl-bc8923b1ec9c467755cd86f7848c50ee8812e441-ssl3_get_server_hello
 * @id cpp/openssl/bc8923b1ec9c467755cd86f7848c50ee8812e441/ssl3-get-server-hello
 * @description openssl-bc8923b1ec9c467755cd86f7848c50ee8812e441-ssl3_get_server_hello CVE-2014-0224
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_822, Parameter vs_818, Variable vj_824) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_818
		and target_0.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="128"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vj_824
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vj_824
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="session_id_length"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_822
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="session_id"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vj_824
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_1(Variable val_823, Parameter vs_818) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sid_ctx_length"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_818
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sid_ctx_length"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_818
		and target_1.getAnOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sid_ctx"
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_818
		and target_1.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="sid_ctx"
		and target_1.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_818
		and target_1.getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="sid_ctx_length"
		and target_1.getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_818
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val_823
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="47"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

from Function func, Variable vp_822, Variable val_823, Parameter vs_818, Variable vj_824
where
not func_0(vp_822, vs_818, vj_824)
and vp_822.getType().hasName("unsigned char *")
and vs_818.getType().hasName("SSL *")
and func_1(val_823, vs_818)
and vj_824.getType().hasName("unsigned int")
and vp_822.getParentScope+() = func
and val_823.getParentScope+() = func
and vs_818.getParentScope+() = func
and vj_824.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
