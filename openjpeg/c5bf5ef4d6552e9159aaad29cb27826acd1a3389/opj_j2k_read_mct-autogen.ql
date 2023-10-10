/**
 * @name openjpeg-c5bf5ef4d6552e9159aaad29cb27826acd1a3389-opj_j2k_read_mct
 * @id cpp/openjpeg/c5bf5ef4d6552e9159aaad29cb27826acd1a3389/opj-j2k-read-mct
 * @description openjpeg-c5bf5ef4d6552e9159aaad29cb27826acd1a3389-src/lib/openjp2/j2k.c-opj_j2k_read_mct CVE-2016-9581
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_5489, Variable vl_tcp_5490, Variable vnew_mct_records_5539, EqualityOperation target_1, EqualityOperation target_2, ExprStmt target_3, NotExpr target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnew_mct_records_5539
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="m_mct_records"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_5490
		and target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_5489
		and target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_5489
		and target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="m_nb_mcc_records"
		and target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_5490
		and target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getUpdate().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_5489
		and target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="m_decorrelation_array"
		and target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("opj_simple_mcc_decorrelation_data_t *")
		and target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="m_offset_array"
		and target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("opj_simple_mcc_decorrelation_data_t *")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vl_tcp_5490, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="m_nb_mct_records"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_5490
		and target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="m_nb_max_mct_records"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_5490
}

predicate func_2(Variable vi_5489, Variable vl_tcp_5490, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vi_5489
		and target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="m_nb_mct_records"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_5490
}

predicate func_3(Variable vl_tcp_5490, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="m_nb_mct_records"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_5490
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_4(Variable vnew_mct_records_5539, NotExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vnew_mct_records_5539
}

from Function func, Variable vi_5489, Variable vl_tcp_5490, Variable vnew_mct_records_5539, EqualityOperation target_1, EqualityOperation target_2, ExprStmt target_3, NotExpr target_4
where
not func_0(vi_5489, vl_tcp_5490, vnew_mct_records_5539, target_1, target_2, target_3, target_4)
and func_1(vl_tcp_5490, target_1)
and func_2(vi_5489, vl_tcp_5490, target_2)
and func_3(vl_tcp_5490, target_3)
and func_4(vnew_mct_records_5539, target_4)
and vi_5489.getType().hasName("OPJ_UINT32")
and vl_tcp_5490.getType().hasName("opj_tcp_t *")
and vnew_mct_records_5539.getType().hasName("opj_mct_data_t *")
and vi_5489.getParentScope+() = func
and vl_tcp_5490.getParentScope+() = func
and vnew_mct_records_5539.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
