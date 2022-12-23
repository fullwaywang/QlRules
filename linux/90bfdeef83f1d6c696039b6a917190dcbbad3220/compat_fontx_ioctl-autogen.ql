/**
 * @name linux-90bfdeef83f1d6c696039b6a917190dcbbad3220-compat_fontx_ioctl
 * @id cpp/linux/90bfdeef83f1d6c696039b6a917190dcbbad3220/compat-fontx-ioctl
 * @description linux-90bfdeef83f1d6c696039b6a917190dcbbad3220-compat_fontx_ioctl 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Variable vvc_cons, Variable vfg_console) {
	exists(ValueFieldAccess target_2 |
		target_2.getTarget().getName()="d"
		and target_2.getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvc_cons
		and target_2.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vfg_console)
}

from Function func, Variable vvc_cons, Variable vfg_console
where
func_2(vvc_cons, vfg_console)
and vvc_cons.getType().hasName("vc[63]")
and vfg_console.getType().hasName("int")
and not vvc_cons.getParentScope+() = func
and not vfg_console.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
