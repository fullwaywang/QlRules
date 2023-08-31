/**
 * @name postgresql-049e1e2edb06854d7cd9460c22516efaa165fbf8-_readModifyTable
 * @id cpp/postgresql/049e1e2edb06854d7cd9460c22516efaa165fbf8/-readModifyTable
 * @description postgresql-049e1e2edb06854d7cd9460c22516efaa165fbf8-src/backend/nodes/readfuncs.c-_readModifyTable CVE-2021-32028
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SizeofTypeOperator target_0) {
		target_0.getType() instanceof LongType
		and target_0.getValue()="232"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, SizeofTypeOperator target_1) {
		target_1.getType() instanceof LongType
		and target_1.getValue()="232"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, SizeofTypeOperator target_2) {
		target_2.getType() instanceof LongType
		and target_2.getValue()="232"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, SizeofTypeOperator target_3) {
		target_3.getType() instanceof LongType
		and target_3.getValue()="232"
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vlocal_node_1680, ExprStmt target_7, ExprStmt target_8, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="onConflictCols"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlocal_node_1680
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("nodeRead")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(54)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(54).getFollowingStmt()=target_4)
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Variable vtoken_1680, Variable vlength_1680, ExprStmt target_9, AddressOfExpr target_10, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtoken_1680
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pg_strtok")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vlength_1680
		and (func.getEntryPoint().(BlockStmt).getStmt(61)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(61).getFollowingStmt()=target_5)
		and target_9.getExpr().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_10.getOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_7(Variable vlocal_node_1680, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlocal_node_1680
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("nodeRead")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_8(Variable vlocal_node_1680, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="onConflictWhere"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlocal_node_1680
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("nodeRead")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_9(Variable vtoken_1680, ExprStmt target_9) {
		target_9.getExpr().(VariableAccess).getTarget()=vtoken_1680
}

predicate func_10(Variable vlength_1680, AddressOfExpr target_10) {
		target_10.getOperand().(VariableAccess).getTarget()=vlength_1680
}

from Function func, Variable vlocal_node_1680, Variable vtoken_1680, Variable vlength_1680, SizeofTypeOperator target_0, SizeofTypeOperator target_1, SizeofTypeOperator target_2, SizeofTypeOperator target_3, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, AddressOfExpr target_10
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and not func_4(vlocal_node_1680, target_7, target_8, func)
and not func_5(vtoken_1680, vlength_1680, target_9, target_10, func)
and func_7(vlocal_node_1680, target_7)
and func_8(vlocal_node_1680, target_8)
and func_9(vtoken_1680, target_9)
and func_10(vlength_1680, target_10)
and vlocal_node_1680.getType().hasName("ModifyTable *")
and vtoken_1680.getType().hasName("const char *")
and vlength_1680.getType().hasName("int")
and vlocal_node_1680.(LocalVariable).getFunction() = func
and vtoken_1680.(LocalVariable).getFunction() = func
and vlength_1680.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
