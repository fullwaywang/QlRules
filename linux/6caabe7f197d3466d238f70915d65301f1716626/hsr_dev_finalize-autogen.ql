/**
 * @name linux-6caabe7f197d3466d238f70915d65301f1716626-hsr_dev_finalize
 * @id cpp/linux/6caabe7f197d3466d238f70915d65301f1716626/hsr-dev-finalize
 * @description linux-6caabe7f197d3466d238f70915d65301f1716626-hsr_dev_finalize 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func) {
	exists(LabelStmt target_1 |
		target_1.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(31)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(31).getFollowingStmt()=target_1))
}

predicate func_2(Variable vhsr_444, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("hsr_del_node")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="self_node_db"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhsr_444
		and (func.getEntryPoint().(BlockStmt).getStmt(32)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(32).getFollowingStmt()=target_2))
}

predicate func_3(Variable vres_446) {
	exists(ReturnStmt target_3 |
		target_3.getExpr().(VariableAccess).getTarget()=vres_446
		and target_3.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vres_446)
}

predicate func_5(Variable vhsr_444) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="ports"
		and target_5.getQualifier().(VariableAccess).getTarget()=vhsr_444)
}

from Function func, Variable vhsr_444, Variable vres_446
where
not func_1(func)
and not func_2(vhsr_444, func)
and func_3(vres_446)
and vhsr_444.getType().hasName("hsr_priv *")
and func_5(vhsr_444)
and vres_446.getType().hasName("int")
and vhsr_444.getParentScope+() = func
and vres_446.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
