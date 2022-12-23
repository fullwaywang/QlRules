/**
 * @name linux-1ebb71143758f45dc0fa76e2f48429e13b16d110-cp_report_fixup
 * @id cpp/linux/1ebb71143758f45dc0fa76e2f48429e13b16d110/cp-report-fixup
 * @description linux-1ebb71143758f45dc0fa76e2f48429e13b16d110-cp_report_fixup 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrsize_34, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vrsize_34
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_0.getThen() instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vrdesc_33, Function func) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(VariableAccess).getTarget()=vrdesc_33
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1))
}

predicate func_3(Variable vi_37, Variable v__tmp_46, Parameter vrdesc_33) {
	exists(ArrayExpr target_3 |
		target_3.getArrayBase().(VariableAccess).getTarget()=vrdesc_33
		and target_3.getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_37
		and target_3.getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_3.getParent().(AssignExpr).getLValue() = target_3
		and target_3.getParent().(AssignExpr).getRValue().(VariableAccess).getTarget()=v__tmp_46)
}

from Function func, Parameter vrsize_34, Variable vi_37, Variable v__tmp_46, Parameter vrdesc_33
where
not func_0(vrsize_34, func)
and not func_1(vrdesc_33, func)
and vrsize_34.getType().hasName("unsigned int *")
and vrdesc_33.getType().hasName("__u8 *")
and func_3(vi_37, v__tmp_46, vrdesc_33)
and vrsize_34.getParentScope+() = func
and vi_37.getParentScope+() = func
and v__tmp_46.getParentScope+() = func
and vrdesc_33.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
