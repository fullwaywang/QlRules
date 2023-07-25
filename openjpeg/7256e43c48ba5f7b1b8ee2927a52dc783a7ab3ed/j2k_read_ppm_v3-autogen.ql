/**
 * @name openjpeg-7256e43c48ba5f7b1b8ee2927a52dc783a7ab3ed-j2k_read_ppm_v3
 * @id cpp/openjpeg/7256e43c48ba5f7b1b8ee2927a52dc783a7ab3ed/j2k-read-ppm-v3
 * @description openjpeg-7256e43c48ba5f7b1b8ee2927a52dc783a7ab3ed-src/lib/openjp2/j2k.c-j2k_read_ppm_v3 CVE-2014-7945
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_header_size_3520, Parameter vp_manager_3521, Variable vl_cp_3524, VariableAccess target_1, IfStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vp_header_size_3520
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ppm_data"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_cp_3524
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ppm_data"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_cp_3524
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ppm_buffer"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_cp_3524
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ppm_len"
		and target_0.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_cp_3524
		and target_0.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ppm"
		and target_0.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_cp_3524
		and target_0.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_0.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_3521
		and target_0.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Error reading PPM marker\n"
		and target_0.getThen().(BlockStmt).getStmt(6).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getCondition().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation())
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_6.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_header_size_3520, VariableAccess target_1) {
		target_1.getTarget()=vp_header_size_3520
}

predicate func_2(Parameter vp_header_size_3520, IfStmt target_2) {
		target_2.getCondition().(VariableAccess).getTarget()=vp_header_size_3520
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_read_bytes_LE")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="4"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="4"
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vp_header_size_3520
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="4"
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_header_size_3520
		and target_2.getElse().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
}

predicate func_3(Parameter vp_header_size_3520, ExprStmt target_3) {
		target_3.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vp_header_size_3520
		and target_3.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="4"
}

predicate func_4(Parameter vp_manager_3521, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_3521
		and target_4.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_4.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Not enough memory to increase the size of ppm_data to add the new Ippm series\n"
}

predicate func_5(Parameter vp_manager_3521, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_3521
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_5.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Not enough memory to increase the size of ppm_data to add the new (complete) Ippm series\n"
}

predicate func_6(Variable vl_cp_3524, ExprStmt target_6) {
		target_6.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ppm_data_read"
		and target_6.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_cp_3524
}

predicate func_7(Variable vl_cp_3524, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("realloc")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ppm_data"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_cp_3524
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="ppm_len"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_cp_3524
}

from Function func, Parameter vp_header_size_3520, Parameter vp_manager_3521, Variable vl_cp_3524, VariableAccess target_1, IfStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7
where
not func_0(vp_header_size_3520, vp_manager_3521, vl_cp_3524, target_1, target_2, target_3, target_4, target_5, target_6, target_7)
and func_1(vp_header_size_3520, target_1)
and func_2(vp_header_size_3520, target_2)
and func_3(vp_header_size_3520, target_3)
and func_4(vp_manager_3521, target_4)
and func_5(vp_manager_3521, target_5)
and func_6(vl_cp_3524, target_6)
and func_7(vl_cp_3524, target_7)
and vp_header_size_3520.getType().hasName("OPJ_UINT32")
and vp_manager_3521.getType().hasName("opj_event_mgr *")
and vl_cp_3524.getType().hasName("opj_cp_t *")
and vp_header_size_3520.getParentScope+() = func
and vp_manager_3521.getParentScope+() = func
and vl_cp_3524.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
