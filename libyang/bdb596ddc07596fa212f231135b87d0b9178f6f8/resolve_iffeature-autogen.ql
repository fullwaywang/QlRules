/**
 * @name libyang-bdb596ddc07596fa212f231135b87d0b9178f6f8-resolve_iffeature
 * @id cpp/libyang/bdb596ddc07596fa212f231135b87d0b9178f6f8/resolve-iffeature
 * @description libyang-bdb596ddc07596fa212f231135b87d0b9178f6f8-src/resolve.c-resolve_iffeature CVE-2019-20391
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vexpr_1401, BlockStmt target_2, IfStmt target_3) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="expr"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexpr_1401
		and target_0.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="features"
		and target_0.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexpr_1401
		and target_0.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vexpr_1401, BlockStmt target_2, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="expr"
		and target_1.getQualifier().(VariableAccess).getTarget()=vexpr_1401
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vexpr_1401, BlockStmt target_2) {
		target_2.getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("resolve_iffeature_recursive")
		and target_2.getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpr_1401
}

predicate func_3(Parameter vexpr_1401, IfStmt target_3) {
		target_3.getCondition().(PointerFieldAccess).getTarget().getName()="expr"
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexpr_1401
		and target_3.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("resolve_iffeature_recursive")
		and target_3.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpr_1401
}

from Function func, Parameter vexpr_1401, PointerFieldAccess target_1, BlockStmt target_2, IfStmt target_3
where
not func_0(vexpr_1401, target_2, target_3)
and func_1(vexpr_1401, target_2, target_1)
and func_2(vexpr_1401, target_2)
and func_3(vexpr_1401, target_3)
and vexpr_1401.getType().hasName("lys_iffeature *")
and vexpr_1401.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
