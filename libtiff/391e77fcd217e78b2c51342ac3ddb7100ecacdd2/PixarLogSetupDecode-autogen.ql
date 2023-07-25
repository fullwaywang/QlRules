/**
 * @name libtiff-391e77fcd217e78b2c51342ac3ddb7100ecacdd2-PixarLogSetupDecode
 * @id cpp/libtiff/391e77fcd217e78b2c51342ac3ddb7100ecacdd2/PixarLogSetupDecode
 * @description libtiff-391e77fcd217e78b2c51342ac3ddb7100ecacdd2-libtiff/tif_pixarlog.c-PixarLogSetupDecode CVE-2016-5315
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsp_675, Variable vtbuf_size_676, EqualityOperation target_1, EqualityOperation target_2, ExprStmt target_3, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tbuf_size"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_675
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtbuf_size_676
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_0)
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsp_675, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="tbuf"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_675
		and target_1.getAnOperand().(Literal).getValue()="0"
}

predicate func_2(Variable vsp_675, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="user_datafmt"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_675
		and target_2.getAnOperand().(UnaryMinusExpr).getValue()="-1"
}

predicate func_3(Variable vsp_675, Variable vtbuf_size_676, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tbuf"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_675
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFmalloc")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtbuf_size_676
}

from Function func, Variable vsp_675, Variable vtbuf_size_676, EqualityOperation target_1, EqualityOperation target_2, ExprStmt target_3
where
not func_0(vsp_675, vtbuf_size_676, target_1, target_2, target_3, func)
and func_1(vsp_675, target_1)
and func_2(vsp_675, target_2)
and func_3(vsp_675, vtbuf_size_676, target_3)
and vsp_675.getType().hasName("PixarLogState *")
and vtbuf_size_676.getType().hasName("tmsize_t")
and vsp_675.(LocalVariable).getFunction() = func
and vtbuf_size_676.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
