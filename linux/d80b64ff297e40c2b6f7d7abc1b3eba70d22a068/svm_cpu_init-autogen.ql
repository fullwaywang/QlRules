/**
 * @name linux-d80b64ff297e40c2b6f7d7abc1b3eba70d22a068-svm_cpu_init
 * @id cpp/linux/d80b64ff297e40c2b6f7d7abc1b3eba70d22a068/svm_cpu_init
 * @description linux-d80b64ff297e40c2b6f7d7abc1b3eba70d22a068-svm_cpu_init 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="12"
		and not target_0.getValue()="0"
		and target_0.getParent().(UnaryMinusExpr).getParent().(AssignExpr).getRValue() instanceof UnaryMinusExpr
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vsd_1007) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("__free_pages")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="save_area"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsd_1007
		and target_1.getArgument(1).(Literal).getValue()="0")
}

predicate func_3(Variable vr_1008) {
	exists(UnaryMinusExpr target_3 |
		target_3.getValue()="-12"
		and target_3.getOperand().(Literal).getValue()="12"
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_1008)
}

predicate func_4(Function func) {
	exists(DeclStmt target_4 |
		func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

predicate func_5(Variable vr_1008) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(VariableAccess).getTarget()=vr_1008
		and target_5.getRValue() instanceof UnaryMinusExpr)
}

predicate func_6(Variable vr_1008) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_1008
		and target_6.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-12"
		and target_6.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand() instanceof Literal
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("svm_sev_enabled"))
}

predicate func_7(Variable vr_1008) {
	exists(VariableAccess target_7 |
		target_7.getTarget()=vr_1008)
}

predicate func_8(Variable vsd_1007) {
	exists(PointerFieldAccess target_8 |
		target_8.getTarget().getName()="cpu"
		and target_8.getQualifier().(VariableAccess).getTarget()=vsd_1007)
}

from Function func, Variable vsd_1007, Variable vr_1008
where
func_0(func)
and not func_1(vsd_1007)
and func_3(vr_1008)
and func_4(func)
and func_5(vr_1008)
and func_6(vr_1008)
and func_7(vr_1008)
and vsd_1007.getType().hasName("svm_cpu_data *")
and func_8(vsd_1007)
and vr_1008.getType().hasName("int")
and vsd_1007.getParentScope+() = func
and vr_1008.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
