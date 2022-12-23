/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-lbs_mesh_show
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/lbs-mesh-show
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-lbs_mesh_show CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_270, Variable vpriv_272) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("snprintf")
		and not target_0.getTarget().hasName("sysfs_emit")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbuf_270
		and target_0.getArgument(1).(Literal).getValue()="5"
		and target_0.getArgument(2).(StringLiteral).getValue()="0x%X\n"
		and target_0.getArgument(3).(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="mesh_dev"
		and target_0.getArgument(3).(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpriv_272)
}

from Function func, Parameter vbuf_270, Variable vpriv_272
where
func_0(vbuf_270, vpriv_272)
and vbuf_270.getType().hasName("char *")
and vpriv_272.getType().hasName("lbs_private *")
and vbuf_270.getParentScope+() = func
and vpriv_272.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
