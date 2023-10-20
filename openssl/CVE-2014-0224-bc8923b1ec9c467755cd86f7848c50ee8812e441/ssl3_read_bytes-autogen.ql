/**
 * @name openssl-bc8923b1ec9c467755cd86f7848c50ee8812e441-ssl3_read_bytes
 * @id cpp/openssl/bc8923b1ec9c467755cd86f7848c50ee8812e441/ssl3-read-bytes
 * @description openssl-bc8923b1ec9c467755cd86f7848c50ee8812e441-ssl3_read_bytes CVE-2014-0224
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_960, Variable vrr_964) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_960
		and target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="128"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr_964
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="20")
}

predicate func_3(Parameter vs_960, Variable vrr_964) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_3.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_3.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_960
		and target_3.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getValue()="-129"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr_964
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="20")
}

predicate func_5(Variable val_962, Variable vrr_964) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val_962
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="10"
		and target_5.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getTarget().getName()="type"
		and target_5.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr_964)
}

predicate func_6(Parameter vs_960) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="tmp"
		and target_6.getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_960)
}

from Function func, Variable val_962, Parameter vs_960, Variable vrr_964
where
not func_0(vs_960, vrr_964)
and not func_3(vs_960, vrr_964)
and func_5(val_962, vrr_964)
and val_962.getType().hasName("int")
and vs_960.getType().hasName("SSL *")
and func_6(vs_960)
and vrr_964.getType().hasName("SSL3_RECORD *")
and val_962.getParentScope+() = func
and vs_960.getParentScope+() = func
and vrr_964.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
