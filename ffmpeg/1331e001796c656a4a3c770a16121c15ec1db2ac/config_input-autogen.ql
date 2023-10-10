/**
 * @name ffmpeg-1331e001796c656a4a3c770a16121c15ec1db2ac-config_input
 * @id cpp/ffmpeg/1331e001796c656a4a3c770a16121c15ec1db2ac/config-input
 * @description ffmpeg-1331e001796c656a4a3c770a16121c15ec1db2ac-libavfilter/vf_floodfill.c-config_input CVE-2020-22034
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_240, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nb_planes"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_240
		and target_0.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_1(Variable vs_240, ExprStmt target_7) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="nb_planes"
		and target_1.getQualifier().(VariableAccess).getTarget()=vs_240
		and target_1.getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vs_240, ExprStmt target_8, ExprStmt target_9) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="nb_planes"
		and target_2.getQualifier().(VariableAccess).getTarget()=vs_240
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getQualifier().(VariableAccess).getLocation())
		and target_2.getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vinlink_236, FunctionCall target_3) {
		target_3.getTarget().hasName("av_pix_fmt_count_planes")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="format"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinlink_236
}

predicate func_4(Function func, DeclStmt target_4) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Variable vnb_planes_241, SwitchStmt target_10, VariableAccess target_5) {
		target_5.getTarget()=vnb_planes_241
		and target_5.getLocation().isBefore(target_10.getExpr().(VariableAccess).getLocation())
}

predicate func_6(Variable vnb_planes_241, SwitchStmt target_11, VariableAccess target_6) {
		target_6.getTarget()=vnb_planes_241
		and target_11.getExpr().(VariableAccess).getLocation().isBefore(target_6.getLocation())
}

predicate func_7(Variable vs_240, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="set_pixel"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_240
}

predicate func_8(Variable vs_240, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pick_pixel"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_240
}

predicate func_9(Variable vs_240, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="set_pixel"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_240
}

predicate func_10(Variable vs_240, Variable vnb_planes_241, SwitchStmt target_10) {
		target_10.getExpr().(VariableAccess).getTarget()=vnb_planes_241
		and target_10.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="1"
		and target_10.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="set_pixel"
		and target_10.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_240
		and target_10.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="is_same"
		and target_10.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_240
}

predicate func_11(Variable vs_240, Variable vnb_planes_241, SwitchStmt target_11) {
		target_11.getExpr().(VariableAccess).getTarget()=vnb_planes_241
		and target_11.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="1"
		and target_11.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="set_pixel"
		and target_11.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_240
		and target_11.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="is_same"
		and target_11.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_240
}

from Function func, Variable vs_240, Variable vnb_planes_241, Parameter vinlink_236, FunctionCall target_3, DeclStmt target_4, VariableAccess target_5, VariableAccess target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, SwitchStmt target_10, SwitchStmt target_11
where
not func_0(vs_240, func)
and not func_1(vs_240, target_7)
and not func_2(vs_240, target_8, target_9)
and func_3(vinlink_236, target_3)
and func_4(func, target_4)
and func_5(vnb_planes_241, target_10, target_5)
and func_6(vnb_planes_241, target_11, target_6)
and func_7(vs_240, target_7)
and func_8(vs_240, target_8)
and func_9(vs_240, target_9)
and func_10(vs_240, vnb_planes_241, target_10)
and func_11(vs_240, vnb_planes_241, target_11)
and vs_240.getType().hasName("FloodfillContext *")
and vnb_planes_241.getType().hasName("int")
and vinlink_236.getType().hasName("AVFilterLink *")
and vs_240.getParentScope+() = func
and vnb_planes_241.getParentScope+() = func
and vinlink_236.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
