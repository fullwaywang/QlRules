/**
 * @name postgresql-049e1e2edb06854d7cd9460c22516efaa165fbf8-_copyModifyTable
 * @id cpp/postgresql/049e1e2edb06854d7cd9460c22516efaa165fbf8/-copyModifyTable
 * @description postgresql-049e1e2edb06854d7cd9460c22516efaa165fbf8-src/backend/nodes/copyfuncs.c-_copyModifyTable CVE-2021-32028
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

predicate func_4(Parameter vfrom_192, Variable vnewnode_194, ExprStmt target_5, ExprStmt target_6, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="onConflictCols"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnewnode_194
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("copyObjectImpl")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="onConflictCols"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfrom_192
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_4)
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vfrom_192, Variable vnewnode_194, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnewnode_194
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("copyObjectImpl")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfrom_192
}

predicate func_6(Parameter vfrom_192, Variable vnewnode_194, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="onConflictWhere"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnewnode_194
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("copyObjectImpl")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="onConflictWhere"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfrom_192
}

from Function func, Parameter vfrom_192, Variable vnewnode_194, SizeofTypeOperator target_0, SizeofTypeOperator target_1, SizeofTypeOperator target_2, SizeofTypeOperator target_3, ExprStmt target_5, ExprStmt target_6
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and not func_4(vfrom_192, vnewnode_194, target_5, target_6, func)
and func_5(vfrom_192, vnewnode_194, target_5)
and func_6(vfrom_192, vnewnode_194, target_6)
and vfrom_192.getType().hasName("const ModifyTable *")
and vnewnode_194.getType().hasName("ModifyTable *")
and vfrom_192.getFunction() = func
and vnewnode_194.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
