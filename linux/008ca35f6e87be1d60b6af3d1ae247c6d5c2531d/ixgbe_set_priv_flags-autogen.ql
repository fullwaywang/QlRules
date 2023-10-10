/**
 * @name linux-008ca35f6e87be1d60b6af3d1ae247c6d5c2531d-ixgbe_set_priv_flags
 * @id cpp/linux/008ca35f6e87be1d60b6af3d1ae247c6d5c2531d/ixgbe_set_priv_flags
 * @description linux-008ca35f6e87be1d60b6af3d1ae247c6d5c2531d-ixgbe_set_priv_flags CVE-2021-33061
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof IntType
		and func.getEntryPoint().(BlockStmt).getStmt(2)=target_0)
}

predicate func_1(Variable vflags2_3519, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignAndExpr).getLValue().(VariableAccess).getTarget()=vflags2_3519
		and target_1.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getValue()="18446744073709027327"
		and target_1.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(BinaryBitwiseOperation).getValue()="524288"
		and target_1.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="19"
		and func.getEntryPoint().(BlockStmt).getStmt(7)=target_1)
}

predicate func_2(Parameter vpriv_flags_3516, Variable vadapter_3518, Variable vflags2_3519, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vpriv_flags_3516
		and target_2.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="4"
		and target_2.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_2.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="type"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="mac"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hw"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadapter_3518
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("unsigned int")
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="num_vfs"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadapter_3518
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="primary_abort_count"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="vfinfo"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadapter_3518
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("unsigned int")
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vflags2_3519
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="19"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="msg_enable"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadapter_3518
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("netdev_info")
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="netdev"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadapter_3518
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Cannot set private flags: Operation not supported\n"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="95"
		and func.getEntryPoint().(BlockStmt).getStmt(8)=target_2)
}

predicate func_9(Parameter vpriv_flags_3516, Variable vflags2_3519) {
	exists(BitwiseAndExpr target_9 |
		target_9.getLeftOperand().(VariableAccess).getTarget()=vpriv_flags_3516
		and target_9.getRightOperand().(BinaryBitwiseOperation).getValue()="2"
		and target_9.getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_9.getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_9.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vflags2_3519
		and target_9.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_9.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="18")
}

predicate func_10(Variable vadapter_3518) {
	exists(PointerFieldAccess target_10 |
		target_10.getTarget().getName()="flags2"
		and target_10.getQualifier().(VariableAccess).getTarget()=vadapter_3518)
}

predicate func_11(Parameter vnetdev_3516, Variable vadapter_3518, Variable vflags2_3519) {
	exists(EqualityOperation target_11 |
		target_11.getAnOperand().(VariableAccess).getTarget()=vflags2_3519
		and target_11.getAnOperand().(PointerFieldAccess).getTarget().getName()="flags2"
		and target_11.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadapter_3518
		and target_11.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags2"
		and target_11.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadapter_3518
		and target_11.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vflags2_3519
		and target_11.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("netif_running")
		and target_11.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnetdev_3516
		and target_11.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ixgbe_reinit_locked")
		and target_11.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vadapter_3518)
}

from Function func, Parameter vnetdev_3516, Parameter vpriv_flags_3516, Variable vadapter_3518, Variable vflags2_3519
where
not func_0(func)
and not func_1(vflags2_3519, func)
and not func_2(vpriv_flags_3516, vadapter_3518, vflags2_3519, func)
and vpriv_flags_3516.getType().hasName("u32")
and func_9(vpriv_flags_3516, vflags2_3519)
and vadapter_3518.getType().hasName("ixgbe_adapter *")
and func_10(vadapter_3518)
and vflags2_3519.getType().hasName("unsigned int")
and func_11(vnetdev_3516, vadapter_3518, vflags2_3519)
and vnetdev_3516.getParentScope+() = func
and vpriv_flags_3516.getParentScope+() = func
and vadapter_3518.getParentScope+() = func
and vflags2_3519.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
