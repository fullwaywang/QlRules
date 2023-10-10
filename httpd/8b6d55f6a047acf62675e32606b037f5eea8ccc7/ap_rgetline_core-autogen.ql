/**
 * @name httpd-8b6d55f6a047acf62675e32606b037f5eea8ccc7-ap_rgetline_core
 * @id cpp/httpd/8b6d55f6a047acf62675e32606b037f5eea8ccc7/ap-rgetline-core
 * @description httpd-8b6d55f6a047acf62675e32606b037f5eea8ccc7-server/protocol.c-ap_rgetline_core CVE-2022-37436
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_216, Parameter vread_217, RelationalOperation target_1, PointerDereferenceExpr target_2, ExprStmt target_3) {
	exists(DoStmt target_0 |
		target_0.getCondition() instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("const server_rec *")
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="level"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(BitwiseAndExpr).getValue()="7"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ap_log_data_")
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="7"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("const server_rec *")
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="NULL bytes in header"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vs_216
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vread_217
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(8) instanceof Literal
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getOperand().(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vread_217, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(VariableAccess).getTarget().getType().hasName("apr_size_t")
		and target_1.getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vread_217
}

predicate func_2(Parameter vs_216, PointerDereferenceExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vs_216
}

predicate func_3(Parameter vread_217, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vread_217
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("apr_size_t")
}

from Function func, Parameter vs_216, Parameter vread_217, RelationalOperation target_1, PointerDereferenceExpr target_2, ExprStmt target_3
where
not func_0(vs_216, vread_217, target_1, target_2, target_3)
and func_1(vread_217, target_1)
and func_2(vs_216, target_2)
and func_3(vread_217, target_3)
and vs_216.getType().hasName("char **")
and vread_217.getType().hasName("apr_size_t *")
and vs_216.getFunction() = func
and vread_217.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
