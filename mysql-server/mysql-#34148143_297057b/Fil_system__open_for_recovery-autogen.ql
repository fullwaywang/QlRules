/**
 * @name mysql-server-297057b5358eb6966a95cd1bd73378f8da943e51-Fil_system__open_for_recovery
 * @id cpp/mysql-server/297057b5358eb6966a95cd1bd73378f8da943e51/filsystemopenforrecovery
 * @description mysql-server-297057b5358eb6966a95cd1bd73378f8da943e51-storage/innobase/fil/fil0fil.cc-Fil_system__open_for_recovery mysql-#34148143
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
exists(LogicalOrExpr target_0 |
	target_0.getLeftOperand() instanceof FunctionCall
	and target_0.getRightOperand().(VariableAccess).getType().hasName("bool")
	and target_0.getEnclosingFunction() = func
)
}

predicate func_1(Variable vspace_9845, FunctionCall target_1) {
	exists(PointerFieldAccess obj_0 | obj_0=target_1.getArgument(0) |
		obj_0.getTarget().getName()="flags"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vspace_9845
	)
	and target_1.getTarget().hasName("FSP_FLAGS_GET_ENCRYPTION")
}

from Function func, Variable vspace_9845, FunctionCall target_1
where
not func_0(func)
and func_1(vspace_9845, target_1)
and vspace_9845.getType().hasName("fil_space_t *")
and vspace_9845.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
