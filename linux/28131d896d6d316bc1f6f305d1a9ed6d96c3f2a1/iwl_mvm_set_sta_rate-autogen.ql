/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_set_sta_rate
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-mvm-set-sta-rate
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_set_sta_rate CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_47(Function func) {
	exists(Literal target_47 |
		target_47.getValue()="10"
		and not target_47.getValue()="0"
		and target_47.getParent().(LShiftExpr).getParent().(BitwiseAndExpr).getRightOperand() instanceof BinaryBitwiseOperation
		and target_47.getEnclosingFunction() = func)
}

predicate func_48(Parameter vrate_n_flags_4874) {
	exists(VariableAccess target_48 |
		target_48.getTarget()=vrate_n_flags_4874
		and target_48.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall)
}

predicate func_49(Function func) {
	exists(Literal target_49 |
		target_49.getValue()="15"
		and not target_49.getValue()="8"
		and target_49.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
		and target_49.getEnclosingFunction() = func)
}

predicate func_53(Function func) {
	exists(Literal target_53 |
		target_53.getValue()="255"
		and not target_53.getValue()="8"
		and target_53.getParent().(FunctionCall).getParent().(SwitchStmt).getExpr() instanceof FunctionCall
		and target_53.getEnclosingFunction() = func)
}

predicate func_54(Parameter vrate_n_flags_4874, Function func) {
	exists(DeclStmt target_54 |
		target_54.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vrate_n_flags_4874
		and target_54.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="7"
		and target_54.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and func.getEntryPoint().(BlockStmt).getStmt(0)=target_54)
}

predicate func_60(Function func) {
	exists(ReturnStmt target_60 |
		target_60.toString() = "return ..."
		and target_60.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("u32")
		and target_60.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="0"
		and target_60.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_60.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("u32")
		and target_60.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof BinaryBitwiseOperation
		and target_60.getEnclosingFunction() = func)
}

predicate func_61(Parameter vrate_n_flags_4874, Parameter vrinfo_4874) {
	exists(ConditionalExpr target_61 |
		target_61.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("u32")
		and target_61.getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getValue()="512"
		and target_61.getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="2"
		and target_61.getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_61.getThen().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vrate_n_flags_4874
		and target_61.getThen().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_61.getThen().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="4"
		and target_61.getThen().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand() instanceof Literal
		and target_61.getThen().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vrate_n_flags_4874
		and target_61.getThen().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="7"
		and target_61.getElse() instanceof FunctionCall
		and target_61.getParent().(AssignExpr).getRValue() = target_61
		and target_61.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mcs"
		and target_61.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874)
}

predicate func_63(Parameter vrate_n_flags_4874, Parameter vrinfo_4874) {
	exists(EqualityOperation target_63 |
		target_63.getAnOperand().(VariableAccess).getType().hasName("u32")
		and target_63.getAnOperand().(BinaryBitwiseOperation).getValue()="1024"
		and target_63.getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="4"
		and target_63.getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_63.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getTarget().hasName("u32_get_bits")
		and target_63.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrate_n_flags_4874
		and target_63.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="7"
		and target_63.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="20"
		and target_63.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_63.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition() instanceof BitwiseAndExpr
		and target_63.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bw"
		and target_63.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_63.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="he_ru_alloc"
		and target_63.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874)
}

predicate func_64(Function func) {
	exists(EqualityOperation target_64 |
		target_64.getAnOperand().(VariableAccess).getType().hasName("u32")
		and target_64.getAnOperand().(Literal).getValue()="3"
		and target_64.getParent().(IfStmt).getThen() instanceof ExprStmt
		and target_64.getEnclosingFunction() = func)
}

predicate func_65(Function func) {
	exists(IfStmt target_65 |
		target_65.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("u32")
		and target_65.getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getValue()="512"
		and target_65.getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="2"
		and target_65.getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_65.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_65.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("u32")
		and target_65.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getValue()="768"
		and target_65.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="3"
		and target_65.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_65.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_65 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_65))
}

predicate func_73(Parameter vrate_n_flags_4874) {
	exists(FunctionCall target_73 |
		target_73.getTarget().hasName("u32_get_bits")
		and target_73.getArgument(0).(VariableAccess).getTarget()=vrate_n_flags_4874
		and target_73.getArgument(1).(Literal).getValue()="15")
}

predicate func_74(Parameter vrinfo_4874) {
	exists(PointerFieldAccess target_74 |
		target_74.getTarget().getName()="flags"
		and target_74.getQualifier().(VariableAccess).getTarget()=vrinfo_4874)
}

predicate func_75(Parameter vrinfo_4874) {
	exists(ExprStmt target_75 |
		target_75.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_75.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_75.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof BitwiseAndExpr)
}

predicate func_77(Parameter vrinfo_4874, Variable vgi_ltf_4907) {
	exists(ExprStmt target_77 |
		target_77.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="he_gi"
		and target_77.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_77.getParent().(IfStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vgi_ltf_4907
		and target_77.getParent().(IfStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="2")
}

predicate func_78(Parameter vrinfo_4874, Variable vgi_ltf_4907) {
	exists(ExprStmt target_78 |
		target_78.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="he_gi"
		and target_78.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_78.getParent().(IfStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vgi_ltf_4907
		and target_78.getParent().(IfStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="2")
}

predicate func_79(Parameter vrinfo_4874, Variable vgi_ltf_4907) {
	exists(IfStmt target_79 |
		target_79.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vgi_ltf_4907
		and target_79.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_79.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vgi_ltf_4907
		and target_79.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_79.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="he_gi"
		and target_79.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_79.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vgi_ltf_4907
		and target_79.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_79.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="he_gi"
		and target_79.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_79.getElse().(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="he_gi"
		and target_79.getElse().(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874)
}

predicate func_80(Parameter vrinfo_4874, Variable vgi_ltf_4907) {
	exists(IfStmt target_80 |
		target_80.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vgi_ltf_4907
		and target_80.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_80.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vgi_ltf_4907
		and target_80.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_80.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="he_gi"
		and target_80.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_80.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="he_gi"
		and target_80.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874)
}

predicate func_81(Parameter vrate_n_flags_4874, Parameter vrinfo_4874) {
	exists(IfStmt target_81 |
		target_81.getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vrate_n_flags_4874
		and target_81.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="262144"
		and target_81.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_81.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="18"
		and target_81.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="he_dcm"
		and target_81.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_81.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_81.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof BitwiseAndExpr)
}

predicate func_82(Parameter vrinfo_4874) {
	exists(ExprStmt target_82 |
		target_82.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="legacy"
		and target_82.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_82.getExpr().(AssignExpr).getRValue().(Literal).getValue()="10")
}

predicate func_83(Parameter vrinfo_4874) {
	exists(ExprStmt target_83 |
		target_83.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="legacy"
		and target_83.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_83.getExpr().(AssignExpr).getRValue().(Literal).getValue()="20")
}

predicate func_84(Parameter vrinfo_4874) {
	exists(ExprStmt target_84 |
		target_84.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="legacy"
		and target_84.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_84.getExpr().(AssignExpr).getRValue().(Literal).getValue()="55")
}

predicate func_85(Parameter vrinfo_4874) {
	exists(ExprStmt target_85 |
		target_85.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="legacy"
		and target_85.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_85.getExpr().(AssignExpr).getRValue().(Literal).getValue()="110")
}

predicate func_86(Parameter vrinfo_4874) {
	exists(ExprStmt target_86 |
		target_86.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="legacy"
		and target_86.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_86.getExpr().(AssignExpr).getRValue().(Literal).getValue()="60")
}

predicate func_87(Parameter vrinfo_4874) {
	exists(ExprStmt target_87 |
		target_87.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="legacy"
		and target_87.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_87.getExpr().(AssignExpr).getRValue().(Literal).getValue()="90")
}

predicate func_88(Parameter vrinfo_4874) {
	exists(ExprStmt target_88 |
		target_88.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="legacy"
		and target_88.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_88.getExpr().(AssignExpr).getRValue().(Literal).getValue()="120")
}

predicate func_89(Parameter vrinfo_4874) {
	exists(ExprStmt target_89 |
		target_89.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="legacy"
		and target_89.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_89.getExpr().(AssignExpr).getRValue().(Literal).getValue()="180")
}

predicate func_90(Parameter vrinfo_4874) {
	exists(ExprStmt target_90 |
		target_90.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="legacy"
		and target_90.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_90.getExpr().(AssignExpr).getRValue().(Literal).getValue()="240")
}

predicate func_91(Parameter vrinfo_4874) {
	exists(ExprStmt target_91 |
		target_91.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="legacy"
		and target_91.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_91.getExpr().(AssignExpr).getRValue().(Literal).getValue()="360")
}

predicate func_92(Parameter vrinfo_4874) {
	exists(ExprStmt target_92 |
		target_92.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="legacy"
		and target_92.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_92.getExpr().(AssignExpr).getRValue().(Literal).getValue()="480")
}

predicate func_93(Parameter vrinfo_4874) {
	exists(ExprStmt target_93 |
		target_93.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="legacy"
		and target_93.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_93.getExpr().(AssignExpr).getRValue().(Literal).getValue()="540")
}

predicate func_96(Function func) {
	exists(LabelStmt target_96 |
		target_96.toString() = "label ...:"
		and target_96.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof BitwiseAndExpr
		and target_96.getEnclosingFunction() = func)
}

predicate func_97(Function func) {
	exists(BreakStmt target_97 |
		target_97.toString() = "break;"
		and target_97.getEnclosingFunction() = func)
}

predicate func_108(Parameter vrinfo_4874) {
	exists(ExprStmt target_108 |
		target_108.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mcs"
		and target_108.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_108.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_108.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof BitwiseAndExpr)
}

predicate func_109(Parameter vrate_n_flags_4874, Parameter vrinfo_4874) {
	exists(ExprStmt target_109 |
		target_109.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nss"
		and target_109.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrinfo_4874
		and target_109.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("u32_get_bits")
		and target_109.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrate_n_flags_4874
		and target_109.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1) instanceof BinaryBitwiseOperation
		and target_109.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand() instanceof Literal
		and target_109.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof BitwiseAndExpr)
}

predicate func_110(Function func) {
	exists(AssignOrExpr target_110 |
		target_110.getLValue() instanceof PointerFieldAccess
		and target_110.getRValue() instanceof EnumConstantAccess
		and target_110.getEnclosingFunction() = func)
}

predicate func_114(Parameter vrate_n_flags_4874) {
	exists(FunctionCall target_114 |
		target_114.getTarget().hasName("u32_get_bits")
		and target_114.getArgument(0).(VariableAccess).getTarget()=vrate_n_flags_4874
		and target_114.getArgument(1) instanceof Literal)
}

from Function func, Parameter vrate_n_flags_4874, Parameter vrinfo_4874, Variable vgi_ltf_4907
where
func_47(func)
and func_48(vrate_n_flags_4874)
and func_49(func)
and func_53(func)
and not func_54(vrate_n_flags_4874, func)
and not func_60(func)
and not func_61(vrate_n_flags_4874, vrinfo_4874)
and not func_63(vrate_n_flags_4874, vrinfo_4874)
and not func_64(func)
and not func_65(func)
and func_73(vrate_n_flags_4874)
and func_74(vrinfo_4874)
and func_75(vrinfo_4874)
and func_77(vrinfo_4874, vgi_ltf_4907)
and func_78(vrinfo_4874, vgi_ltf_4907)
and func_79(vrinfo_4874, vgi_ltf_4907)
and func_80(vrinfo_4874, vgi_ltf_4907)
and func_81(vrate_n_flags_4874, vrinfo_4874)
and func_82(vrinfo_4874)
and func_83(vrinfo_4874)
and func_84(vrinfo_4874)
and func_85(vrinfo_4874)
and func_86(vrinfo_4874)
and func_87(vrinfo_4874)
and func_88(vrinfo_4874)
and func_89(vrinfo_4874)
and func_90(vrinfo_4874)
and func_91(vrinfo_4874)
and func_92(vrinfo_4874)
and func_93(vrinfo_4874)
and func_96(func)
and func_97(func)
and func_108(vrinfo_4874)
and func_109(vrate_n_flags_4874, vrinfo_4874)
and func_110(func)
and func_114(vrate_n_flags_4874)
and vrate_n_flags_4874.getType().hasName("u32")
and vrinfo_4874.getType().hasName("rate_info *")
and vgi_ltf_4907.getType().hasName("u32")
and vrate_n_flags_4874.getParentScope+() = func
and vrinfo_4874.getParentScope+() = func
and vgi_ltf_4907.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
