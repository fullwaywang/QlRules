/**
 * @name wavpack-4bc05fc490b66ef2d45b1de26abf1455b486b0dc-read_new_config_info
 * @id cpp/wavpack/4bc05fc490b66ef2d45b1de26abf1455b486b0dc/read-new-config-info
 * @description wavpack-4bc05fc490b66ef2d45b1de26abf1455b486b0dc-src/open_utils.c-read_new_config_info CVE-2016-10169
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbytecnt_549, BlockStmt target_7, RelationalOperation target_8, ExprStmt target_9) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vbytecnt_549
		and target_0.getLesserOperand().(Literal).getValue()="2"
		and target_0.getParent().(IfStmt).getThen()=target_7
		and target_8.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_9.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vnchans_571, Variable vi_571, Parameter vwpc_547, VariableAccess target_6, RelationalOperation target_10, ExprStmt target_11, ExprStmt target_12) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="channel_reordering"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_547
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_571
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnchans_571
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="channel_reordering"
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_547
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_571
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_10.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_2(Variable vbytecnt_549, BlockStmt target_7, VariableAccess target_2) {
		target_2.getTarget()=vbytecnt_549
		and target_2.getParent().(IfStmt).getThen()=target_7
}

predicate func_3(Variable vbytecnt_549, BlockStmt target_13, VariableAccess target_3) {
		target_3.getTarget()=vbytecnt_549
		and target_3.getParent().(IfStmt).getThen()=target_13
}

predicate func_4(Variable vbytecnt_549, BlockStmt target_14, VariableAccess target_4) {
		target_4.getTarget()=vbytecnt_549
		and target_4.getParent().(IfStmt).getThen()=target_14
}

predicate func_5(Variable vbytecnt_549, BlockStmt target_15, VariableAccess target_5) {
		target_5.getTarget()=vbytecnt_549
		and target_5.getParent().(IfStmt).getThen()=target_15
}

predicate func_6(Variable vbytecnt_549, BlockStmt target_16, VariableAccess target_6) {
		target_6.getTarget()=vbytecnt_549
		and target_6.getParent().(IfStmt).getThen()=target_16
}

predicate func_7(Parameter vwpc_547, BlockStmt target_7) {
		target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="file_format"
		and target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_547
		and target_7.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="qmode"
		and target_7.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="config"
		and target_7.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_547
		and target_7.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="qmode"
		and target_7.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="config"
		and target_7.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getValue()="-256"
}

predicate func_8(Variable vnchans_571, Variable vbytecnt_549, RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getGreaterOperand().(VariableAccess).getTarget()=vbytecnt_549
		and target_8.getLesserOperand().(VariableAccess).getTarget()=vnchans_571
}

predicate func_9(Variable vbytecnt_549, ExprStmt target_9) {
		target_9.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vbytecnt_549
}

predicate func_10(Variable vnchans_571, Variable vi_571, RelationalOperation target_10) {
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getLesserOperand().(VariableAccess).getTarget()=vi_571
		and target_10.getGreaterOperand().(VariableAccess).getTarget()=vnchans_571
}

predicate func_11(Variable vi_571, Parameter vwpc_547, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="channel_reordering"
		and target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_547
		and target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_571
}

predicate func_12(Variable vi_571, Parameter vwpc_547, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="channel_reordering"
		and target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_547
		and target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_571
		and target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vi_571
}

predicate func_13(Variable vnchans_571, Variable vbytecnt_549, Parameter vwpc_547, BlockStmt target_13) {
		target_13.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="channel_layout"
		and target_13.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_547
		and target_13.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="16"
		and target_13.getStmt(2).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vbytecnt_549
		and target_13.getStmt(3).(IfStmt).getCondition().(VariableAccess).getTarget()=vbytecnt_549
		and target_13.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="channel_layout"
		and target_13.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_547
		and target_13.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnchans_571
		and target_13.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vbytecnt_549
		and target_13.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(VariableAccess).getTarget()=vbytecnt_549
		and target_13.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="channel_reordering"
		and target_13.getStmt(3).(IfStmt).getElse().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="channel_layout"
		and target_13.getStmt(3).(IfStmt).getElse().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_547
		and target_13.getStmt(3).(IfStmt).getElse().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(ValueFieldAccess).getTarget().getName()="num_channels"
		and target_13.getStmt(3).(IfStmt).getElse().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="config"
		and target_13.getStmt(3).(IfStmt).getElse().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_547
}

predicate func_14(Variable vnchans_571, Variable vbytecnt_549, Parameter vwpc_547, BlockStmt target_14) {
		target_14.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="channel_layout"
		and target_14.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_547
		and target_14.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnchans_571
		and target_14.getStmt(1).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vbytecnt_549
		and target_14.getStmt(2).(IfStmt).getCondition().(VariableAccess).getTarget()=vbytecnt_549
		and target_14.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbytecnt_549
		and target_14.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnchans_571
		and target_14.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_14.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="channel_reordering"
		and target_14.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_547
		and target_14.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("malloc")
		and target_14.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnchans_571
}

predicate func_15(Variable vnchans_571, Variable vbytecnt_549, Parameter vwpc_547, BlockStmt target_15) {
		target_15.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbytecnt_549
		and target_15.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnchans_571
		and target_15.getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_15.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="channel_reordering"
		and target_15.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_547
		and target_15.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("malloc")
		and target_15.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnchans_571
}

predicate func_16(Variable vi_571, Variable vbytecnt_549, Parameter vwpc_547, BlockStmt target_16) {
		target_16.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="channel_reordering"
		and target_16.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_547
		and target_16.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_571
		and target_16.getStmt(1).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vbytecnt_549
}

from Function func, Variable vnchans_571, Variable vi_571, Variable vbytecnt_549, Parameter vwpc_547, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, VariableAccess target_6, BlockStmt target_7, RelationalOperation target_8, ExprStmt target_9, RelationalOperation target_10, ExprStmt target_11, ExprStmt target_12, BlockStmt target_13, BlockStmt target_14, BlockStmt target_15, BlockStmt target_16
where
not func_0(vbytecnt_549, target_7, target_8, target_9)
and not func_1(vnchans_571, vi_571, vwpc_547, target_6, target_10, target_11, target_12)
and func_2(vbytecnt_549, target_7, target_2)
and func_3(vbytecnt_549, target_13, target_3)
and func_4(vbytecnt_549, target_14, target_4)
and func_5(vbytecnt_549, target_15, target_5)
and func_6(vbytecnt_549, target_16, target_6)
and func_7(vwpc_547, target_7)
and func_8(vnchans_571, vbytecnt_549, target_8)
and func_9(vbytecnt_549, target_9)
and func_10(vnchans_571, vi_571, target_10)
and func_11(vi_571, vwpc_547, target_11)
and func_12(vi_571, vwpc_547, target_12)
and func_13(vnchans_571, vbytecnt_549, vwpc_547, target_13)
and func_14(vnchans_571, vbytecnt_549, vwpc_547, target_14)
and func_15(vnchans_571, vbytecnt_549, vwpc_547, target_15)
and func_16(vi_571, vbytecnt_549, vwpc_547, target_16)
and vnchans_571.getType().hasName("int")
and vi_571.getType().hasName("int")
and vbytecnt_549.getType().hasName("int")
and vwpc_547.getType().hasName("WavpackContext *")
and vnchans_571.getParentScope+() = func
and vi_571.getParentScope+() = func
and vbytecnt_549.getParentScope+() = func
and vwpc_547.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
