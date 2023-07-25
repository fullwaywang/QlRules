/**
 * @name wireshark-4a948427100b6c109f4ec7b4361f0d2aec5e5c3f-proto_register_blip
 * @id cpp/wireshark/4a948427100b6c109f4ec7b4361f0d2aec5e5c3f/proto-register-blip
 * @description wireshark-4a948427100b6c109f4ec7b4361f0d2aec5e5c3f-epan/dissectors/packet-blip.c-proto_register_blip CVE-2020-25866
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("expert_module_t *")
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("ei_register_info[1]")
		and target_0.getExpr().(FunctionCall).getArgument(2).(DivExpr).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0))
}

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("prefs_register_uint_preference")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("module_t *")
		and target_1.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="max_uncompressed_size"
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Maximum uncompressed message size (Kb)"
		and target_1.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="The maximum size of the buffer for uncompressed messages. If a message is larger than this, then the packet containing the message, as well as subsequent packets, will fail to decompress"
		and target_1.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="10"
		and target_1.getExpr().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("guint")
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_1))
}

from Function func
where
not func_0(func)
and not func_1(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
