/**
 * @name ffmpeg-c898431ca5ef2a997fe9388b650f658fb60783e5-nsv_read_header
 * @id cpp/ffmpeg/c898431ca5ef2a997fe9388b650f658fb60783e5/nsv-read-header
 * @description ffmpeg-c898431ca5ef2a997fe9388b650f658fb60783e5-libavformat/nsvdec.c-nsv_read_header CVE-2011-3940
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable verr_524, EqualityOperation target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=verr_524
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=verr_524
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3)
}

predicate func_1(Variable verr_524, EqualityOperation target_4, ExprStmt target_5) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=verr_524
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=verr_524
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable verr_524, Parameter vs_521, EqualityOperation target_3, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_524
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("nsv_parse_NSVf_header")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_521
		and target_2.getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(EqualityOperation target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("NSVContext *")
}

predicate func_4(EqualityOperation target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("NSVContext *")
}

predicate func_5(Variable verr_524, Parameter vs_521, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_524
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("nsv_parse_NSVs_header")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_521
}

from Function func, Variable verr_524, Parameter vs_521, ExprStmt target_2, EqualityOperation target_3, EqualityOperation target_4, ExprStmt target_5
where
not func_0(verr_524, target_3)
and not func_1(verr_524, target_4, target_5)
and func_2(verr_524, vs_521, target_3, target_2)
and func_3(target_3)
and func_4(target_4)
and func_5(verr_524, vs_521, target_5)
and verr_524.getType().hasName("int")
and vs_521.getType().hasName("AVFormatContext *")
and verr_524.(LocalVariable).getFunction() = func
and vs_521.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
