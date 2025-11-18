<template>
  <div>
    <v-row>
        <v-col cols="12" md="4">
          <v-text-field label="API Token" v-model="token" type="password" append-icon="mdi-key" />
        </v-col>
        <v-col cols="12" md="4">
          <v-select
            :items="groupNames"
            label="Grupos"
            v-model="selected"
            @change="onGroupChange"
          />
        </v-col>
        <v-col cols="12" md="4" class="d-flex align-center">
          <v-btn color="error" :disabled="!selected" @click="confirmBlock">
            Bloquear IPs del grupo
          </v-btn>
          <v-btn color="primary" class="ml-3" :disabled="!selected" @click="confirmUnblock">
            Desbloquear IPs del grupo
          </v-btn>
        </v-col>
      </v-row>

    <v-row>
      <v-col cols="12">
        <v-list two-line>
          <v-subheader>IPs del grupo</v-subheader>
          <v-list-item v-for="ip in ips" :key="ip">
            <v-list-item-content>
              <v-list-item-title>{{ ip }}</v-list-item-title>
            </v-list-item-content>
          </v-list-item>
          <v-list-item v-if="ips.length === 0">
            <v-list-item-content>
              <v-list-item-title>No hay IPs para este grupo</v-list-item-title>
            </v-list-item-content>
          </v-list-item>
        </v-list>
      </v-col>
    </v-row>

    <v-dialog v-model="confirm.show" max-width="500">
      <v-card>
        <v-card-title>{{ confirm.title }}</v-card-title>
        <v-card-text>{{ confirm.text }}</v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn text @click="confirm.show = false">Cancelar</v-btn>
          <v-btn color="error" @click="doConfirm">Confirmar</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <v-snackbar v-model="snackbar.show" :color="snackbar.color" top>
      {{ snackbar.message }}
      <template #actions>
        <v-btn text @click="snackbar.show = false">Cerrar</v-btn>
      </template>
    </v-snackbar>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import axios from 'axios'

const data = ref<{ groups: Record<string, string[]>, blocked: string[] }>({ groups: {}, blocked: [] })
const selected = ref<string | null>(null)
const ips = ref<string[]>([])
const snackbar = ref({ show: false, message: '', color: 'info' })
const token = ref('')
const confirm = ref({ show: false, action: '', title: '', text: '' })

let pendingAction: null | 'block' | 'unblock' = null

const fetchData = async () => {
  try {
    const res = await axios.get('/api/list')
    data.value = res.data
  } catch (e) {
    snackbar.value = { show: true, message: 'Error al obtener datos', color: 'error' }
  }
}

const groupNames = computed(() => Object.keys(data.value.groups || {}))

const onGroupChange = (val?: any) => {
  // support v-select passing the new value or relying on v-model
  const key = (typeof val === 'string') ? val : selected.value
  if (!key) {
    ips.value = []
    return
  }
  ips.value = (data.value.groups && data.value.groups[key]) || []
}

// also update ips whenever selected changes (robust for different v-select behaviors)
watch(selected, (newVal) => {
  const key = (typeof newVal === 'string') ? newVal : newVal
  if (!key) {
    ips.value = []
    return
  }
  ips.value = (data.value.groups && data.value.groups[key]) || []
})

const blockSelected = async () => {
  if (!selected.value) return
  try {
    const headers: Record<string,string> = {}
    if (token.value) headers['x-api-key'] = token.value
    const res = await axios.post('/api/block', { name: selected.value }, { headers })
    const ok = res.data && res.data.ok
    if (ok) {
      snackbar.value = { show: true, message: `Bloqueado: ${selected.value}`, color: 'success' }
      await fetchData()
    } else {
      snackbar.value = { show: true, message: `Fallo al bloquear: ${res.data.message || 'unknown'}`, color: 'warning' }
    }
  } catch (e) {
    snackbar.value = { show: true, message: 'Error al conectar al API', color: 'error' }
  }
}

const unblockSelected = async () => {
  if (!selected.value) return
  try {
    const headers: Record<string,string> = {}
    if (token.value) headers['x-api-key'] = token.value
    const res = await axios.post('/api/unblock', { name: selected.value }, { headers })
    const ok = res.data && res.data.ok
    if (ok) {
      snackbar.value = { show: true, message: `Desbloqueado: ${selected.value}`, color: 'success' }
      await fetchData()
    } else {
      snackbar.value = { show: true, message: `Fallo al desbloquear: ${res.data.message || 'unknown'}`, color: 'warning' }
    }
  } catch (e) {
    snackbar.value = { show: true, message: 'Error al conectar al API', color: 'error' }
  }
}

const confirmBlock = () => {
  if (!selected.value) return
  confirm.value = { show: true, action: 'block', title: 'Confirmar bloqueo', text: `¿Bloquear todas las IPs del grupo "${selected.value}"?` }
}

const confirmUnblock = () => {
  if (!selected.value) return
  confirm.value = { show: true, action: 'unblock', title: 'Confirmar desbloqueo', text: `¿Eliminar las reglas de bloqueo para el grupo "${selected.value}"?` }
}

const doConfirm = async () => {
  confirm.value.show = false
  if (confirm.value.action === 'block') await blockSelected()
  else if (confirm.value.action === 'unblock') await unblockSelected()
}

onMounted(async () => {
  await fetchData()
})
</script>

<style scoped>
.v-list { max-width: 720px; }
</style>
