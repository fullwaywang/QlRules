/**
 * @name linux-f8be156be163a052a067306417cd0ff679068c97-hva_to_pfn_remapped
 * @id cpp/linux/f8be156be163a052a067306417cd0ff679068c97/hva-to-pfn-remapped
 * @description linux-f8be156be163a052a067306417cd0ff679068c97-hva_to_pfn_remapped CVE-2021-22543
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="0"
		and not target_0.getValue()="14"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vpfn_2063, Variable vr_2066, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("kvm_try_get_pfn")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpfn_2063
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_2066
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-14"
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="14"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_1))
}

predicate func_5(Variable vpfn_2063) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("kvm_get_pfn")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vpfn_2063)
}

from Function func, Variable vpfn_2063, Variable vr_2066
where
func_0(func)
and not func_1(vpfn_2063, vr_2066, func)
and func_5(vpfn_2063)
and vpfn_2063.getType().hasName("kvm_pfn_t")
and vr_2066.getType().hasName("int")
and vpfn_2063.getParentScope+() = func
and vr_2066.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
