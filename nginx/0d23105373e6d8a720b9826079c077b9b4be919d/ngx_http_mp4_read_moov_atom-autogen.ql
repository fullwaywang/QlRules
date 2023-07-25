/**
 * @name nginx-0d23105373e6d8a720b9826079c077b9b4be919d-ngx_http_mp4_read_moov_atom
 * @id cpp/nginx/0d23105373e6d8a720b9826079c077b9b4be919d/ngx-http-mp4-read-moov-atom
 * @description nginx-0d23105373e6d8a720b9826079c077b9b4be919d-src/http/modules/ngx_http_mp4_module.c-ngx_http_mp4_read_moov_atom CVE-2022-41742
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vmp4_1163, LogicalAndExpr target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(ValueFieldAccess).getTarget().getName()="buf"
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="moov_atom"
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmp4_1163
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="log_level"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="log"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="file"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ngx_log_error_core")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="log"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="file"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="duplicate mp4 moov atom in \"%s\""
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="data"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="name"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0)
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vmp4_1163, LogicalAndExpr target_1) {
		target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("ngx_uint_t")
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="start"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmp4_1163
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmp4_1163
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vmp4_1163, LogicalAndExpr target_1
where
not func_0(vmp4_1163, target_1, func)
and func_1(vmp4_1163, target_1)
and vmp4_1163.getType().hasName("ngx_http_mp4_file_t *")
and vmp4_1163.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
