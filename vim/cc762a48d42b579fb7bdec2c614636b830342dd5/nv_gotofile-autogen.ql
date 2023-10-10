/**
 * @name vim-cc762a48d42b579fb7bdec2c614636b830342dd5-nv_gotofile
 * @id cpp/vim/cc762a48d42b579fb7bdec2c614636b830342dd5/nv-gotofile
 * @description vim-cc762a48d42b579fb7bdec2c614636b830342dd5-src/normal.c-nv_gotofile CVE-2022-4141
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcap_4024, FunctionCall target_0) {
		target_0.getTarget().hasName("check_text_locked")
		and not target_0.getTarget().hasName("check_text_or_curbuf_locked")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="oap"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcap_4024
}

predicate func_1(Parameter vcap_4024, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="oap"
		and target_1.getQualifier().(VariableAccess).getTarget()=vcap_4024
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_2(Parameter vcap_4024, Function func, IfStmt target_2) {
		target_2.getCondition().(FunctionCall).getTarget().hasName("curbuf_locked")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("clearop")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="oap"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcap_4024
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).toString() = "return ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

/*predicate func_3(Parameter vcap_4024, FunctionCall target_5, FunctionCall target_0, ExprStmt target_6, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("clearop")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="oap"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcap_4024
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
/*predicate func_4(FunctionCall target_5, Function func, ReturnStmt target_4) {
		target_4.toString() = "return ..."
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_4.getEnclosingFunction() = func
}

*/
predicate func_5(FunctionCall target_5) {
		target_5.getTarget().hasName("curbuf_locked")
}

predicate func_6(Parameter vcap_4024, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("grab_file_name")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="count1"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcap_4024
}

from Function func, Parameter vcap_4024, FunctionCall target_0, PointerFieldAccess target_1, IfStmt target_2, FunctionCall target_5, ExprStmt target_6
where
func_0(vcap_4024, target_0)
and func_1(vcap_4024, target_1)
and func_2(vcap_4024, func, target_2)
and func_5(target_5)
and func_6(vcap_4024, target_6)
and vcap_4024.getType().hasName("cmdarg_T *")
and vcap_4024.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
