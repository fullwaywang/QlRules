/**
 * @name openjpeg-1a8318f6c24623189ecb65e049267c6f2e005c0e-opj_t2_read_packet_header
 * @id cpp/openjpeg/1a8318f6c24623189ecb65e049267c6f2e005c0e/opj-t2-read-packet-header
 * @description openjpeg-1a8318f6c24623189ecb65e049267c6f2e005c0e-src/lib/openjp2/t2.c-opj_t2_read_packet_header CVE-2016-1924
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_pi_839, Parameter vp_manager_845, Variable vl_band_857, NotExpr target_2, AddressOfExpr target_3, AddressOfExpr target_4, ExprStmt target_5, ExprStmt target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="precno"
		and target_0.getCondition().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_pi_839
		and target_0.getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(DivExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="precincts_data_size"
		and target_0.getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(DivExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_band_857
		and target_0.getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getValue()="56"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_845
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid precinct\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(DivExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vl_band_857, NotExpr target_2) {
		target_2.getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="x1"
		and target_2.getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_band_857
		and target_2.getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="x0"
		and target_2.getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_band_857
		and target_2.getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="y1"
		and target_2.getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_band_857
		and target_2.getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="y0"
		and target_2.getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_band_857
		and target_2.getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Parameter vp_pi_839, Variable vl_band_857, AddressOfExpr target_3) {
		target_3.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="precincts"
		and target_3.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_band_857
		and target_3.getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="precno"
		and target_3.getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_pi_839
}

predicate func_4(Parameter vp_pi_839, Variable vl_band_857, AddressOfExpr target_4) {
		target_4.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="precincts"
		and target_4.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_band_857
		and target_4.getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="precno"
		and target_4.getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_pi_839
}

predicate func_5(Parameter vp_manager_845, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_845
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_5.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Not enough space for expected SOP marker\n"
}

predicate func_6(Variable vl_band_857, ExprStmt target_6) {
		target_6.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vl_band_857
}

from Function func, Parameter vp_pi_839, Parameter vp_manager_845, Variable vl_band_857, NotExpr target_2, AddressOfExpr target_3, AddressOfExpr target_4, ExprStmt target_5, ExprStmt target_6
where
not func_0(vp_pi_839, vp_manager_845, vl_band_857, target_2, target_3, target_4, target_5, target_6)
and func_2(vl_band_857, target_2)
and func_3(vp_pi_839, vl_band_857, target_3)
and func_4(vp_pi_839, vl_band_857, target_4)
and func_5(vp_manager_845, target_5)
and func_6(vl_band_857, target_6)
and vp_pi_839.getType().hasName("opj_pi_iterator_t *")
and vp_manager_845.getType().hasName("opj_event_mgr_t *")
and vl_band_857.getType().hasName("opj_tcd_band_t *")
and vp_pi_839.getParentScope+() = func
and vp_manager_845.getParentScope+() = func
and vl_band_857.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
