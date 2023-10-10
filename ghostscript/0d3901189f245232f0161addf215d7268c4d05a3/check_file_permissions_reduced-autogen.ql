/**
 * @name ghostscript-0d3901189f245232f0161addf215d7268c4d05a3-check_file_permissions_reduced
 * @id cpp/ghostscript/0d3901189f245232f0161addf215d7268c4d05a3/check-file-permissions-reduced
 * @description ghostscript-0d3901189f245232f0161addf215d7268c4d05a3-psi/zfile.c-check_file_permissions_reduced CVE-2018-15908
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter viodev_124, BlockStmt target_2, EqualityOperation target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=viodev_124
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vi_ctx_p_123, Parameter viodev_124, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=viodev_124
		and target_1.getAnOperand().(FunctionCall).getTarget().hasName("gs_getiodevice")
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="current"
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_123
		and target_1.getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

from Function func, Parameter vi_ctx_p_123, Parameter viodev_124, EqualityOperation target_1, BlockStmt target_2
where
not func_0(viodev_124, target_2, target_1)
and func_1(vi_ctx_p_123, viodev_124, target_2, target_1)
and func_2(target_2)
and vi_ctx_p_123.getType().hasName("i_ctx_t *")
and viodev_124.getType().hasName("gx_io_device *")
and vi_ctx_p_123.getFunction() = func
and viodev_124.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
