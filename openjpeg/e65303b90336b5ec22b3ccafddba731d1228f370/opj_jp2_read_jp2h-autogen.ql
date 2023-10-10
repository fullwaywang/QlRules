/**
 * @name openjpeg-e65303b90336b5ec22b3ccafddba731d1228f370-opj_jp2_read_jp2h
 * @id cpp/openjpeg/e65303b90336b5ec22b3ccafddba731d1228f370/opj-jp2-read-jp2h
 * @description openjpeg-e65303b90336b5ec22b3ccafddba731d1228f370-src/lib/openjp2/jp2.c-opj_jp2_read_jp2h CVE-2014-7945
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbox_2171, ExprStmt target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="type"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbox_2171
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1768449138"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("OPJ_BOOL")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignSubExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_manager_2167, NotExpr target_4, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("OPJ_BOOL")
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_2167
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Stream error while reading JP2 Header box: no 'ihdr' box.\n"
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_1)
		and target_4.getOperand().(VariableCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vbox_2171, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="length"
		and target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbox_2171
}

predicate func_3(Variable vbox_2171, ExprStmt target_3) {
		target_3.getExpr().(AssignSubExpr).getRValue().(ValueFieldAccess).getTarget().getName()="length"
		and target_3.getExpr().(AssignSubExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbox_2171
}

predicate func_4(Parameter vp_manager_2167, NotExpr target_4) {
		target_4.getOperand().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="handler"
		and target_4.getOperand().(VariableCall).getArgument(3).(VariableAccess).getTarget()=vp_manager_2167
}

from Function func, Parameter vp_manager_2167, Variable vbox_2171, ExprStmt target_2, ExprStmt target_3, NotExpr target_4
where
not func_0(vbox_2171, target_2, target_3)
and not func_1(vp_manager_2167, target_4, func)
and func_2(vbox_2171, target_2)
and func_3(vbox_2171, target_3)
and func_4(vp_manager_2167, target_4)
and vp_manager_2167.getType().hasName("opj_event_mgr_t *")
and vbox_2171.getType().hasName("opj_jp2_box_t")
and vp_manager_2167.getParentScope+() = func
and vbox_2171.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
