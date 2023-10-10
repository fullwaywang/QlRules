/**
 * @name libtiff-33aee1275d9d1384791d2206776eb8152d397f00-computeInputPixelOffsets
 * @id cpp/libtiff/33aee1275d9d1384791d2206776eb8152d397f00/computeInputPixelOffsets
 * @description libtiff-33aee1275d9d1384791d2206776eb8152d397f00-tools/tiffcrop.c-computeInputPixelOffsets CVE-2023-0800
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_5818, Variable vzlength_5818, Parameter vcrop_5806, PointerFieldAccess target_2, ArrayExpr target_3, ExprStmt target_4, ExprStmt target_5, SwitchStmt target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_5818
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vzlength_5818
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="combined_length"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5806
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="computeInputPixelOffsets"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Only equal length regions can be combined for -E left or right"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_2
		and target_3.getArrayOffset().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_6.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vi_5818, Variable vzwidth_5818, Parameter vcrop_5806, PointerFieldAccess target_2, ExprStmt target_7, ExprStmt target_8) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_5818
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vzwidth_5818
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="combined_width"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5806
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="computeInputPixelOffsets"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Only equal width regions can be combined for -E top or bottom"
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_2
		and target_7.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vcrop_5806, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="edge_ref"
		and target_2.getQualifier().(VariableAccess).getTarget()=vcrop_5806
}

predicate func_3(Variable vi_5818, Parameter vcrop_5806, ArrayExpr target_3) {
		target_3.getArrayBase().(PointerFieldAccess).getTarget().getName()="regionlist"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5806
		and target_3.getArrayOffset().(VariableAccess).getTarget()=vi_5818
}

predicate func_4(Variable vzlength_5818, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="spp"
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(DivExpr).getRightOperand().(Literal).getValue()="8"
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vzlength_5818
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_5(Variable vzlength_5818, Parameter vcrop_5806, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="combined_length"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5806
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vzlength_5818
}

predicate func_6(Variable vzlength_5818, Parameter vcrop_5806, SwitchStmt target_6) {
		target_6.getExpr().(PointerFieldAccess).getTarget().getName()="edge_ref"
		and target_6.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5806
		and target_6.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="2"
		and target_6.getStmt().(BlockStmt).getStmt(1).(SwitchCase).getExpr().(Literal).getValue()="4"
		and target_6.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="combined_length"
		and target_6.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5806
		and target_6.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vzlength_5818
}

predicate func_7(Variable vzwidth_5818, Parameter vcrop_5806, ExprStmt target_7) {
		target_7.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="combined_width"
		and target_7.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5806
		and target_7.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vzwidth_5818
}

predicate func_8(Variable vzwidth_5818, Parameter vcrop_5806, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="combined_width"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5806
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vzwidth_5818
}

from Function func, Variable vi_5818, Variable vzwidth_5818, Variable vzlength_5818, Parameter vcrop_5806, PointerFieldAccess target_2, ArrayExpr target_3, ExprStmt target_4, ExprStmt target_5, SwitchStmt target_6, ExprStmt target_7, ExprStmt target_8
where
not func_0(vi_5818, vzlength_5818, vcrop_5806, target_2, target_3, target_4, target_5, target_6)
and not func_1(vi_5818, vzwidth_5818, vcrop_5806, target_2, target_7, target_8)
and func_2(vcrop_5806, target_2)
and func_3(vi_5818, vcrop_5806, target_3)
and func_4(vzlength_5818, target_4)
and func_5(vzlength_5818, vcrop_5806, target_5)
and func_6(vzlength_5818, vcrop_5806, target_6)
and func_7(vzwidth_5818, vcrop_5806, target_7)
and func_8(vzwidth_5818, vcrop_5806, target_8)
and vi_5818.getType().hasName("uint32_t")
and vzwidth_5818.getType().hasName("uint32_t")
and vzlength_5818.getType().hasName("uint32_t")
and vcrop_5806.getType().hasName("crop_mask *")
and vi_5818.(LocalVariable).getFunction() = func
and vzwidth_5818.(LocalVariable).getFunction() = func
and vzlength_5818.(LocalVariable).getFunction() = func
and vcrop_5806.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
