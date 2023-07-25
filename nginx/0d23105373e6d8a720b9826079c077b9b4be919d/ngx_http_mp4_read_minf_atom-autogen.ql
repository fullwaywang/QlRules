/**
 * @name nginx-0d23105373e6d8a720b9826079c077b9b4be919d-ngx_http_mp4_read_minf_atom
 * @id cpp/nginx/0d23105373e6d8a720b9826079c077b9b4be919d/ngx-http-mp4-read-minf-atom
 * @description nginx-0d23105373e6d8a720b9826079c077b9b4be919d-src/http/modules/ngx_http_mp4_module.c-ngx_http_mp4_read_minf_atom CVE-2022-41742
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtrak_1884, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(ValueFieldAccess).getTarget().getName()="buf"
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="out"
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrak_1884
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="7"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="log_level"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="log"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="file"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ngx_log_error_core")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="log"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="file"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="duplicate mp4 minf atom in \"%s\""
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="data"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="name"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vtrak_1884, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtrak_1884
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="elts"
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="trak"
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ngx_http_mp4_file_t *")
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="nelts"
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="trak"
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_2(Variable vtrak_1884, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("ngx_buf_t *")
		and target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="minf_atom_buf"
		and target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrak_1884
}

from Function func, Variable vtrak_1884, ExprStmt target_1, ExprStmt target_2
where
not func_0(vtrak_1884, target_1, target_2, func)
and func_1(vtrak_1884, target_1)
and func_2(vtrak_1884, target_2)
and vtrak_1884.getType().hasName("ngx_http_mp4_trak_t *")
and vtrak_1884.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
