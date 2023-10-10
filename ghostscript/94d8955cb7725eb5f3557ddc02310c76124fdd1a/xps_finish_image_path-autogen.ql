/**
 * @name ghostscript-94d8955cb7725eb5f3557ddc02310c76124fdd1a-xps_finish_image_path
 * @id cpp/ghostscript/94d8955cb7725eb5f3557ddc02310c76124fdd1a/xps-finish-image-path
 * @description ghostscript-94d8955cb7725eb5f3557ddc02310c76124fdd1a-devices/vector/gdevxps.c-xps_finish_image_path CVE-2020-16303
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vxps_1422, ExprStmt target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="xps_pie"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vxps_1422
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0)
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vxps_1422, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("write_str_to_current_page")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vxps_1422
		and target_1.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="\t<Path.Fill>\n"
}

from Function func, Variable vxps_1422, ExprStmt target_1
where
not func_0(vxps_1422, target_1, func)
and func_1(vxps_1422, target_1)
and vxps_1422.getType().hasName("gx_device_xps *")
and vxps_1422.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
