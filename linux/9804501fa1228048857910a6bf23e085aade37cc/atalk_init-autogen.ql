/**
 * @name linux-9804501fa1228048857910a6bf23e085aade37cc-atalk_init
 * @id cpp/linux/9804501fa1228048857910a6bf23e085aade37cc/atalk_init
 * @description linux-9804501fa1228048857910a6bf23e085aade37cc-atalk_init 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="2Unable to register DDP with SNAP.\n"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vrc_1913) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vrc_1913
		and target_1.getRValue().(FunctionCall).getTarget().hasName("aarp_proto_init"))
}

predicate func_2(Variable vrc_1913, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(VariableAccess).getTarget()=vrc_1913
		and target_2.getThen().(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_2))
}

predicate func_3(Function func) {
	exists(LabelStmt target_3 |
		target_3.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(29)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(29).getFollowingStmt()=target_3))
}

predicate func_5(Function func) {
	exists(GotoStmt target_5 |
		target_5.toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(33)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(33).getFollowingStmt()=target_5))
}

predicate func_7(Variable vatalk_err_snap) {
	exists(VariableAccess target_7 |
		target_7.getTarget()=vatalk_err_snap
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk"))
}

predicate func_8(Function func) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("aarp_proto_init")
		and target_8.getEnclosingFunction() = func)
}

from Function func, Variable vatalk_err_snap, Variable vrc_1913
where
not func_0(func)
and not func_1(vrc_1913)
and not func_2(vrc_1913, func)
and not func_3(func)
and not func_5(func)
and func_7(vatalk_err_snap)
and func_8(func)
and vrc_1913.getType().hasName("int")
and not vatalk_err_snap.getParentScope+() = func
and vrc_1913.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
