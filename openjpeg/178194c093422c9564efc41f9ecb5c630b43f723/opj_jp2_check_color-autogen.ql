/**
 * @name openjpeg-178194c093422c9564efc41f9ecb5c630b43f723-opj_jp2_check_color
 * @id cpp/openjpeg/178194c093422c9564efc41f9ecb5c630b43f723/opj-jp2-check-color
 * @description openjpeg-178194c093422c9564efc41f9ecb5c630b43f723-src/lib/openjp2/jp2.c-opj_jp2_check_color CVE-2016-9581
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_manager_880, Variable vi_882, Variable vcmap_933, Variable vis_sane_934, ExprStmt target_4, ExprStmt target_5, ArrayExpr target_6, ArrayExpr target_7, ExprStmt target_8) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="mtyp"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vcmap_933
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_882
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="mtyp"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vcmap_933
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_882
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_880
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid value for cmap[%d].mtyp = %d.\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vi_882
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="mtyp"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vcmap_933
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_882
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vis_sane_934
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getElse() instanceof IfStmt
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_6.getArrayOffset().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_7.getArrayOffset().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

/*predicate func_1(Variable vis_sane_934, ExprStmt target_8) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vis_sane_934
		and target_1.getRValue().(Literal).getValue()="0"
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getLValue().(VariableAccess).getLocation()))
}

*/
predicate func_2(Parameter vp_manager_880, Variable vi_882, Variable vnr_channels_932, Variable vcmap_933, Variable vpcol_usage_934, Variable vis_sane_934, Variable vpcol_952, IfStmt target_2) {
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vpcol_952
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnr_channels_932
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_880
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid component/palette index for direct mapping %d.\n"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vpcol_952
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vis_sane_934
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpcol_usage_934
		and target_2.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vpcol_952
		and target_2.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="mtyp"
		and target_2.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vcmap_933
		and target_2.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_882
		and target_2.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_880
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Component %d is mapped twice.\n"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vpcol_952
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vis_sane_934
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="mtyp"
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="pcol"
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_880
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Direct use at #%d however pcol=%d.\n"
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vi_882
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vpcol_952
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vis_sane_934
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_4(Parameter vp_manager_880, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_880
		and target_4.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_4.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected OOM.\n"
}

predicate func_5(Parameter vp_manager_880, Variable vpcol_952, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_880
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_5.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid component/palette index for direct mapping %d.\n"
		and target_5.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vpcol_952
}

predicate func_6(Variable vi_882, Variable vcmap_933, ArrayExpr target_6) {
		target_6.getArrayBase().(VariableAccess).getTarget()=vcmap_933
		and target_6.getArrayOffset().(VariableAccess).getTarget()=vi_882
}

predicate func_7(Variable vi_882, Variable vcmap_933, ArrayExpr target_7) {
		target_7.getArrayBase().(VariableAccess).getTarget()=vcmap_933
		and target_7.getArrayOffset().(VariableAccess).getTarget()=vi_882
}

predicate func_8(Variable vis_sane_934, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vis_sane_934
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vp_manager_880, Variable vi_882, Variable vnr_channels_932, Variable vcmap_933, Variable vpcol_usage_934, Variable vis_sane_934, Variable vpcol_952, IfStmt target_2, ExprStmt target_4, ExprStmt target_5, ArrayExpr target_6, ArrayExpr target_7, ExprStmt target_8
where
not func_0(vp_manager_880, vi_882, vcmap_933, vis_sane_934, target_4, target_5, target_6, target_7, target_8)
and func_2(vp_manager_880, vi_882, vnr_channels_932, vcmap_933, vpcol_usage_934, vis_sane_934, vpcol_952, target_2)
and func_4(vp_manager_880, target_4)
and func_5(vp_manager_880, vpcol_952, target_5)
and func_6(vi_882, vcmap_933, target_6)
and func_7(vi_882, vcmap_933, target_7)
and func_8(vis_sane_934, target_8)
and vp_manager_880.getType().hasName("opj_event_mgr_t *")
and vi_882.getType().hasName("OPJ_UINT16")
and vnr_channels_932.getType().hasName("OPJ_UINT16")
and vcmap_933.getType().hasName("opj_jp2_cmap_comp_t *")
and vpcol_usage_934.getType().hasName("OPJ_BOOL *")
and vis_sane_934.getType().hasName("OPJ_BOOL")
and vpcol_952.getType().hasName("OPJ_UINT16")
and vp_manager_880.getParentScope+() = func
and vi_882.getParentScope+() = func
and vnr_channels_932.getParentScope+() = func
and vcmap_933.getParentScope+() = func
and vpcol_usage_934.getParentScope+() = func
and vis_sane_934.getParentScope+() = func
and vpcol_952.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
